class MonsterPacket:
    TYPE = 1033
    id: str
    
    def __init__(self, packet_id):
        self.id = packet_id
    
    def __str__(self):
        return 'Monster : ' + str(self.id)
    
    @staticmethod
    def parse(data):
        hex_id = data[0:8].hex()
        return MonsterPacket(hex_id)