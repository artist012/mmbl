import logging, threading, queue, time
from functools import lru_cache
from typing import List, Optional, Tuple, Dict
import brotli, pydivert
from websockets.sync.server import serve


DEFAULT_PORT          = 16000
DMG_TYPE_PATTERN      = bytes.fromhex('03 05 00 00')

DATA_TYPE_DOT         = 67
DATA_TYPE_DAMAGE      = 1283
EXCEPTED_DATA_TYPES   = {DATA_TYPE_DOT, DATA_TYPE_DAMAGE}

INVALID_DAMAGE        = 0xffffffff

FLAG_BITS = (
    (0, 'crit',           0x01),
    (0, 'unguarded',      0x04),
    (0, 'guard_break',    0x08),
    (0, 'first_hit',      0x40),
    (0, 'default_attack', 0x80),
    (1, 'multi_hit',      0x01),
    (1, 'power',          0x02),
    (1, 'fast',           0x04),
    (1, 'dot_flag',       0x08),
    (3, 'add_hit',        0x08),
    (3, 'bleed',          0x10),
    (3, 'fire',           0x40),
    (3, 'holy',           0x80),
    (4, 'ice',            0x01),
    (4, 'electric',       0x02),
    (4, 'poison',         0x04),
    (4, 'mind',           0x08),
    (4, 'not_dot',        0x10),
)



logger = logging.getLogger("DamageTrackerWS")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(levelname)s] %(asctime)s: %(message)s"))
logger.addHandler(handler)

@lru_cache(maxsize=256)
def extract_flags(flag_bytes: bytes) -> Dict[str, int]:
    result = {}
    for idx, name, mask in FLAG_BITS:
        result[name] = 1 if idx < len(flag_bytes) and (flag_bytes[idx] & mask) else 0
    return result

def find_pattern(data: bytes, pattern: bytes) -> List[int]:
    pos, out, start = 0, [], 0
    while True:
        pos = data.find(pattern, start)
        if pos == -1:
            break
        out.append(pos)
        start = pos + 1
    return out

def format_log(evt: Dict) -> str:
    ordered = [
        'timestamp', 'used_by', 'target', 'skill_name', 'damage',
        'crit', 'add_hit',
    ]
    print('|'.join(str(evt.get(k, 0)) for k in ordered))
    return '|'.join(str(evt.get(k, 0)) for k in ordered)

# ──────────────────────────────  PacketSniffer  ──────────────────────────────
class PacketSniffer(threading.Thread):
    def __init__(self, port: int, out_q: queue.Queue):
        super().__init__(daemon=True)
        self.port, self.out_q = port, out_q
        self._stop = threading.Event()
        self._buf: List[Tuple[int, bytes]] = []
        self._lock = threading.Lock()

    def stop(self):
        self._stop.set()

    def _assemble_and_flush(self):
        self._buf.sort(key=lambda x: x[0])
        expected, merged, consumed = None, bytearray(), 0
        for i, (seq, chunk) in enumerate(self._buf):
            if expected is None:
                expected = seq
            if seq > expected:
                break
            if seq < expected:
                overlap = expected - seq
                if overlap >= len(chunk):
                    continue
                chunk = chunk[overlap:]
            merged.extend(chunk)
            expected += len(chunk)
            consumed = i + 1
        if merged:
            self.out_q.put(bytes(merged))
        self._buf = self._buf[consumed:]

    def run(self):
        filt = f"tcp and (tcp.SrcPort == {self.port} or tcp.DstPort == {self.port})"
        logger.info(f"Sniffer start port={self.port}")
        with pydivert.WinDivert(filt) as w:
            for pkt in w:
                if self._stop.is_set():
                    break
                w.send(pkt)                      # 그대로 통과
                if not pkt.tcp or not pkt.payload or not pkt.is_inbound:
                    continue
                with self._lock:
                    self._buf.append((pkt.tcp.seq_num, bytes(pkt.payload)))
                    if pkt.tcp.psh or pkt.tcp.fin:
                        self._assemble_and_flush()
        logger.info("Sniffer stopped")

class DamageProcessor(threading.Thread):
    def __init__(self, in_q: queue.Queue, event_q: queue.Queue):
        super().__init__(daemon=True)
        self.in_q, self.event_q = in_q, event_q
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()
        self.in_q.put(None)

    @staticmethod
    def _parse_damage_record(data: bytes) -> Optional[Dict]:
        try:
            uid  = data[0:4].hex()
            tgt  = data[8:12].hex()
            skl_len = int.from_bytes(data[16:20],'little')
            skl_raw = data[20:20+skl_len].replace(b'\x00', b'')
            damage  = int.from_bytes(data[20+skl_len:24+skl_len],'little')
            if damage == INVALID_DAMAGE:
                return None
            flags   = extract_flags(data[36+skl_len:56+skl_len])

            skill_name = skl_raw.decode('utf-8', 'ignore').strip()
            if skl_len == 0:
                prefix = 'DOT' if flags['dot_flag'] else 'UNKNOWN'
                suffix = '_'.join(n.upper() for n in
                                  ('ice','fire','electric','holy','bleed','poison','mind')
                                  if flags.get(n))
                skill_name = f"{prefix}_{suffix}" if suffix else prefix

            return {
                'timestamp': int(time.time()*1000),
                'used_by': uid, 'target': tgt,
                'skill_name': skill_name,
                'skill_id': data[56+skl_len:64+skl_len].hex(),
                'damage': damage, **flags
            }
        except Exception:
            return None

    def _extract_from_payload(self, raw: bytes) -> List[Dict]:
        out = []
        for pos in find_pattern(raw, DMG_TYPE_PATTERN):
            d_type = int.from_bytes(raw[pos:pos+4],'little')
            if d_type not in EXCEPTED_DATA_TYPES:
                continue
            d_len  = int.from_bytes(raw[pos+4:pos+8],'little')
            enc    = raw[pos+8]
            payload= raw[pos+9:pos+9+d_len]
            if enc == 1:
                try:
                    payload = brotli.decompress(payload)
                except brotli.error:
                    continue

            if d_type == DATA_TYPE_DOT:
                tgt  = payload[17:21].hex()
                dmg  = int.from_bytes(payload[29:33],'little')
                flags= extract_flags(payload[33:53])
                evt = {
                    'timestamp': int(time.time()*1000),
                    'used_by': '', 'target': tgt, 'skill_name': 'DOT',
                    'skill_id': payload[53:61].hex(), 'damage': dmg, **flags
                }
                out.append(evt)
            else:
                rec = self._parse_damage_record(payload)
                if rec:
                    out.append(rec)
        return out


    def run(self):
        logger.info("Processor start")
        while not self._stop.is_set():
            try:
                raw = self.in_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if raw is None:
                break
            for evt in self._extract_from_payload(raw):
                self.event_q.put(evt)
            self.in_q.task_done()
        logger.info("Processor stopped")

class WebSocketBroadcaster(threading.Thread):
    def __init__(self, event_q: queue.Queue,
                 host: str = 'localhost', port: int = 8000):
        super().__init__(daemon=True)
        self.event_q = event_q
        self.host, self.port = host, port
        self._shutdown = threading.Event()
        self._ws_lock = threading.Lock()
        self._ws = None

    def stop(self):
        self._shutdown.set()
        with self._ws_lock:
            if self._ws:
                try:
                    self._ws.close()
                except:
                    pass
                self._ws = None

    def _handler(self, websocket):
        logger.info("WS connected")
        with self._ws_lock:
            if self._ws:
                try:
                    self._ws.close()
                except:
                    pass
            self._ws = websocket
        try:
            while not self._shutdown.is_set():
                time.sleep(1)
        finally:
            with self._ws_lock:
                if self._ws == websocket:
                    self._ws = None
            logger.info("WS disconnected")

    def run(self):
        logger.info(f"WebSocket serve ws://{self.host}:{self.port}")
        with serve(self._handler, self.host, self.port) as server:
            accept_thread = threading.Thread(
                target=server.serve_forever, daemon=True)
            accept_thread.start()

            try:
                while not self._shutdown.is_set():
                    try:
                        evt = self.event_q.get(timeout=0.5)
                    except queue.Empty:
                        continue
                    msg = format_log(evt)
                    with self._ws_lock:
                        if self._ws:
                            try:
                                self._ws.send(msg)
                            except Exception as e:
                                logger.warning(f"WS send error: {e}")
                                try:
                                    self._ws.close()
                                except:
                                    pass
                                self._ws = None
                    self.event_q.task_done()
            finally:
                server.close()
                accept_thread.join()



pkt_q   = queue.Queue()
evt_q   = queue.Queue()

sniffer  = PacketSniffer(DEFAULT_PORT, pkt_q)
proc     = DamageProcessor(pkt_q, evt_q)
wss      = WebSocketBroadcaster(evt_q, port=8000)

sniffer.start(); proc.start(); wss.start()

sniffer.join(); proc.join(); wss.join()
logger.info("Exited cleanly")
