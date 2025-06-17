import logging, threading, queue, time
from functools import lru_cache
from typing import List, Optional, Tuple, Dict
from collections import deque
import brotli, pydivert
from websockets.sync.server import serve

DEFAULT_PORT = 16000
DATA_TYPE_DOT = 67
DATA_TYPE_DAMAGE = 1283
DATA_TYPE_SKILL = 1432
EXCEPTED_DATA_TYPES = [DATA_TYPE_DOT, DATA_TYPE_DAMAGE, DATA_TYPE_SKILL]
INVALID_DAMAGE = 0xffffffff

PACKET_START = b'\x3A\x04\x00\x00\x00\x00\x00\x00'
PACKET_END = b'\x04\x00\x00\x00\x00\x00\x00\x00'

FLAG_BITS = (
    (0, 'crit_flag', 0x01),
    (0, 'unguarded_flag', 0x04),
    (0, 'break_flag', 0x08),
    (0, 'first_hit_flag', 0x40),
    (0, 'default_attack_flag', 0x80),
    (1, 'multi_attack_flag', 0x01),
    (1, 'power_flag', 0x02),
    (1, 'fast_flag', 0x04),
    (1, 'dot_flag', 0x08),
    (3, 'add_hit_flag', 0x08),
    (3, 'bleed_flag', 0x10),
    (3, 'fire_flag', 0x40),
    (3, 'holy_flag', 0x80),
    (4, 'ice_flag', 0x01),
    (4, 'electric_flag', 0x02),
    (4, 'poison_flag', 0x04),
    (4, 'mind_flag', 0x08),
    (4, 'not_dot_flag', 0x10),
)

skill_id_mapping = {}
skill_sequence_queue = deque(maxlen=50)
SKILL_TIMEOUT_SEC = 10

logger = logging.getLogger("DamageTracker")
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

def add_skill_with_sequence(name: str, seq: int, ts: float, skill_id: str = None):
    skill_info = {"name": name, "seq": seq, "time": ts, "skill_id": skill_id}
    skill_sequence_queue.append(skill_info)
    if skill_id and skill_id != '00000000':
        skill_id_mapping[skill_id] = name

def get_skill_for_damage(seq: int, ts: float, skill_id: Optional[str]) -> Optional[str]:
    if skill_id and skill_id in skill_id_mapping:
        return skill_id_mapping[skill_id]
    for s in reversed(skill_sequence_queue):
        if s['seq'] <= seq and s['time'] <= ts:
            return s['name']
    return None

def parse_skill_name(content: bytes):
    try:
        skill_name_len = int.from_bytes(content[:4], 'little')
        skill_name = content[4:4+skill_name_len].replace(b'\x00', b'').decode('utf-8', errors='replace')
        skill_id = content[26:30].hex() if len(content) >= 30 else None
        return skill_name, skill_id
    except:
        return None, None

def parse_damage(payload: bytes):
    try:
        uid = payload[:4].hex()
        tgt = payload[8:12].hex()
        skl_len = int.from_bytes(payload[16:20], 'little')
        skl_raw = payload[20:20+skl_len].replace(b'\x00', b'')
        damage = int.from_bytes(payload[20+skl_len:24+skl_len], 'little')
        if damage == INVALID_DAMAGE:
            return None
        flags = extract_flags(payload[36+skl_len:56+skl_len])
        skill_name = skl_raw.decode('utf-8', 'ignore').strip() or "Idle"
        skill_id = payload[56+skl_len:60+skl_len].hex()
        return {
            'timestamp': int(time.time()*1000), 'used_by': uid, 'target': tgt,
            'skill_name': skill_name, 'skill_id': skill_id, 'damage': damage, **flags
        }
    except:
        return None

def extract_packets(data: bytes, types: List[int]) -> List[Tuple[int, bytes, int, int, int]]:
    packets = []
    for t in types:
        pattern = t.to_bytes(4, 'little')
        idx = 0
        while True:
            pos = data.find(pattern, idx)
            if pos == -1: break
            if pos + 8 < len(data):
                try:
                    length = int.from_bytes(data[pos+4:pos+8], 'little')
                    if 1 <= length <= 65536 and pos+9+length <= len(data):
                        enc = data[pos+8]
                        payload = data[pos+9:pos+9+length]
                        if enc == 1:
                            payload = brotli.decompress(payload)
                        packets.append((t, payload, length, pos, pos+9+length))
                except:
                    pass
            idx = pos + 1
    return packets

def parse_packets_from_payload(payload: bytes, seq_num: int, packet_time: float) -> List[Dict]:
    results = []
    for dtype, content, _, _, _ in extract_packets(payload, EXCEPTED_DATA_TYPES):
        if dtype == DATA_TYPE_SKILL:
            skill_name, skill_id = parse_skill_name(content[24:])
            if skill_name:
                add_skill_with_sequence(skill_name, seq_num, packet_time, skill_id)
        elif dtype == DATA_TYPE_DAMAGE:
            rec = parse_damage(content)
            if rec:
                if rec['skill_name'] == 'Idle':
                    guessed = get_skill_for_damage(seq_num, packet_time, rec['skill_id'])
                    if guessed:
                        rec['skill_name'] = guessed
                results.append(rec)
    return results

def format_log(evt: Dict) -> str:
    ordered = ['timestamp', 'used_by', 'target', 'skill_name', 'damage', 'crit_flag', 'add_hit_flag']
    return '|'.join(str(evt.get(k, 0)) for k in ordered)

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
                if self._stop.is_set(): break
                w.send(pkt)
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

    def run(self):
        while not self._stop.is_set():
            try:
                raw = self.in_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if raw is None:
                break
            now = time.time()
            for evt in parse_packets_from_payload(raw, 0, now):
                self.event_q.put(evt)
            self.in_q.task_done()
        logger.info("Processor stopped")

class WebSocketBroadcaster(threading.Thread):
    def __init__(self, event_q: queue.Queue, host: str = 'localhost', port: int = 8000):
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
                try: self._ws.close()
                except: pass
                self._ws = None

    def _handler(self, websocket):
        with self._ws_lock:
            if self._ws:
                try: self._ws.close()
                except: pass
            self._ws = websocket
        try:
            while not self._shutdown.is_set():
                time.sleep(1)
        finally:
            with self._ws_lock:
                if self._ws == websocket:
                    self._ws = None

    def run(self):
        logger.info(f"WebSocket serve ws://{self.host}:{self.port}")
        with serve(self._handler, self.host, self.port) as server:
            accept_thread = threading.Thread(target=server.serve_forever, daemon=True)
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
                            try: self._ws.send(msg)
                            except Exception as e:
                                logger.warning(f"WS send error: {e}")
                                try: self._ws.close()
                                except: pass
                                self._ws = None
                    self.event_q.task_done()
            finally:
                server.close()
                accept_thread.join()






pkt_q = queue.Queue()
evt_q = queue.Queue()

sniffer = PacketSniffer(DEFAULT_PORT, pkt_q)
processor = DamageProcessor(pkt_q, evt_q)
wss = WebSocketBroadcaster(evt_q, port=8000)

sniffer.start(); processor.start(); wss.start()
sniffer.join(); processor.join(); wss.join()
logger.info("Exited cleanly")
