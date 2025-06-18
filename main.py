import socket
import sys
import time
import traceback
import brotli
import os
import shutil
import subprocess
import random
import string
import ctypes
import threading
import pydivert
from websockets.sync.server import serve
from packet.action_packet import ActionPacket
from packet.damage_packet import DamagePacket
from custom_lru_cache import CustomLRUCache
from packet.monster_packet import MonsterPacket
from packet.user_info_packet import UserInfoPacket






last_flush = time.time()
data = b''
DEBUG = False
USER_ID_MAP = CustomLRUCache(64)
MONSTER_ID_MAP = CustomLRUCache(64)
SKILL_ID_TABLE = {}
INVALID_DAMAGE = 4294967295  

def logws(ws, logfile):
    def log(packet_data):
        global data, last_flush

        chunk = packet_data

        if chunk.startswith(b'\xb76\x00\x00'):
            return None

        if chunk == b'\x00\x00\x00\x00\x00\x00':
            return None

        if chunk.startswith(b':\x04\x00\x00\x00\x00\x00\x00'):
            data = chunk
        else:
            data += chunk

        if logfile:
            if time.time() > last_flush + 5000:
                logfile.flush()
                last_flush = time.time()

        while len(data) > 8:
            packet_type = int.from_bytes(data[0:4], byteorder='little')
            payload_length = int.from_bytes(data[4:8], byteorder='little')
            encode_type = data[8]

            if len(data) < 9 + payload_length:
                break

            payload = data[9:9 + payload_length]
            data = data[9 + payload_length:]

            parse_data(packet_type, payload, encode_type, ws, logfile)

    return log

def parse_data(data_type, content, encode_type, ws, logfile):
    try:
        if data_type == MonsterPacket.TYPE:
            if encode_type == 1:
                content = brotli.decompress(content)
            monster = MonsterPacket.parse(content)
            MONSTER_ID_MAP[monster.id] = 1

        if data_type == UserInfoPacket.TYPE:
            
            if encode_type == 1:
                content = brotli.decompress(content)
            user_info = UserInfoPacket.parse(content)
            USER_ID_MAP[user_info.id] = user_info.username

        if data_type == ActionPacket.TYPE:
            if encode_type == 1:
                content = brotli.decompress(content)
            action = ActionPacket.parse(content)
            if action.skill_id not in SKILL_ID_TABLE:
                SKILL_ID_TABLE[action.skill_id] = action.skill_name

        if data_type == DamagePacket.TYPE:
            if encode_type == 1:
                content = brotli.decompress(content)
            damage = DamagePacket.parse(content)

            if damage.used_by in MONSTER_ID_MAP:
                return None

            if damage.used_by in USER_ID_MAP:
                damage.used_by = USER_ID_MAP[damage.used_by]

            if damage.skill_name.startswith('Idle'):
                if damage.skill_id in SKILL_ID_TABLE:
                    damage.skill_name = SKILL_ID_TABLE[damage.skill_id] + '_' + damage.skill_name
            if damage.damage == INVALID_DAMAGE:
                damage.damage = 0
            log_entry = damage.to_log_data()

            if damage.damage != 0xFFFFFFFF:
                if logfile:
                    logfile.write(log_entry + '\n')
                ws.send(log_entry)

    except:
        if DEBUG:
            traceback.print_exc(file=sys.stdout)

def wsserve(websocket):
    print('connected')
    logfile_handle = None
    log_callback = logws(websocket, logfile_handle)

    with pydivert.WinDivert("tcp.DstPort == 16000 or tcp.SrcPort == 16000") as w:
        for packet in w:
            w.send(packet)
            try:
                payload = packet.payload
                if payload:
                    log_callback(payload)
            except Exception as e:
                if DEBUG:
                    traceback.print_exc()


def is_frozen():
    return getattr(sys, 'frozen', False)

def random_filename(extension='.exe'):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + extension

def mutate_binary(path):
    with open(path, 'ab') as f:
        f.write(os.urandom(random.randint(1, 16)))  # 해시 변경 목적의 노이즈

def randomize_title():
    while True:
        title = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        ctypes.windll.kernel32.SetConsoleTitleW(title)
        time.sleep(0.1)

def main():
    if not is_frozen():
        print("EXE 환경에서만 동작합니다.") # 빌드후 사용 혹은 코드제거후 사용
        return

    current_path = sys.executable

    if len(sys.argv) == 2:
        time.sleep(1)  
        original_path = sys.argv[1]
        try:
            os.remove(original_path)
        except Exception as e:
            pass

        threading.Thread(target=randomize_title, daemon=True).start()

        try:
            with serve(wsserve, '0.0.0.0', 8000) as server:
                server.serve_forever()
        except socket.error:
            print('현재 19999번 포트를 사용중이거나 막혀있습니다.')


    else:
        current_dir = os.path.dirname(current_path)
        new_name = random_filename()
        new_path = os.path.join(current_dir, new_name)

        try:
            shutil.copy2(current_path, new_path)
            mutate_binary(new_path)
            subprocess.Popen([new_path, current_path])  # 원본 경로를 인자로 전달
            sys.exit()
        except Exception as e:
            sys.exit(1)

main()