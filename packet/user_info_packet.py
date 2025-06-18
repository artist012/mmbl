class UserInfoPacket:
    TYPE = 1036
    id: str
    username: str
    
    def __init__(self, packet_id, username):
        self.id = packet_id
        self.username = username
    
    def __str__(self):
        return f'{self.id}: {self.username}'
    
    @staticmethod
    def parse(data: bytearray):
        hex_id = data[:8].hex()
        weapon_marker_pos = data.find('Weapon'.encode('utf-16le'))
        trimmed_data = data[weapon_marker_pos:]
        delimiter_pos = trimmed_data.find(bytearray.fromhex('3f00000000'))
        username_data = trimmed_data[delimiter_pos + 5:]
        username_length = int.from_bytes(username_data[:4], byteorder='little')
        username_data = username_data[4:]
        username = username_data[:username_length].decode('utf-16le')
        return UserInfoPacket(hex_id, username)