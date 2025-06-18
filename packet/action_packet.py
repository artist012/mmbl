class ActionPacket:
    TYPE = 10041
    
    used_by: str
    skill_name: str
    skill_id: int
    
    def __init__(self, used_by, skill_name, skill_id):
        self.used_by = used_by
        self.skill_id = skill_id
        self.skill_name = skill_name
    
    def __str__(self):
        return f"{self.used_by} {hex(self.skill_id)} : {self.skill_name}"
    
    @staticmethod
    def parse(data):
        # Parse first 8 bytes as little-endian integer (used_by)
        used_by_int = int.from_bytes(data[:8], byteorder='little')
        data = data[8:]
        
        # Parse next 4 bytes as little-endian integer (skill_name length)
        skill_name_length = int.from_bytes(data[:4], byteorder='little')
        data = data[4:]
        
        # Parse skill_name using utf-16le encoding
        skill_name = data[:skill_name_length].decode('utf-16le')
        data = data[skill_name_length:]
        
        # Parse last 4 bytes as little-endian integer (skill_id)
        skill_id = int.from_bytes(data[-4:], byteorder='little')
        
        return ActionPacket(used_by_int, skill_name, skill_id)