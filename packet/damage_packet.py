import time

DEBUG = False

def flag_check(skill_name, flag, n, bit):
    if DEBUG:
        result = (flag[n] & bit) != 0
        if result:
            print(skill_name, 'flags on ', n, hex(bit))
    return None

class DamagePacket:
    TYPE = 1283
    
    class DamageFlag:
        crit = False
        unguarded = False
        broken = False
        first_hit = False
        multi_hit = False
        flurry_hit = False
        power_hit = False
        add_hit = False
        default_attack = False
        dot = False
        ice = False
        fire = False
        electric = False
        bleed = False
        poison = False
        mind = False
        holy = False
        dark = False
    
    used_by: str
    target: str
    skill_name_length: int
    skill_name: str
    damage: int
    skill_id: int
    flag: DamageFlag
    flag_byte: str
    
    def __init__(self, used_by, target, skill_name_length, skill_name, damage, unknown_null, skill_id, flag, flag_byte):
        self.used_by = used_by
        self.target = target
        self.skill_name_length = skill_name_length
        self.skill_name = skill_name
        self.damage = damage
        self.skill_id = skill_id
        self.flag = flag
        self.flag_byte = flag_byte
    
    def __str__(self):
        return f"{self.used_by}->{self.target}, {self.flag_byte[None:2]} {self.flag_byte[2:4]} {self.flag_byte[4:6]} {self.flag_byte[6:8]} {self.flag_byte[8:10]} {self.flag_byte[10:None]} - {hex(self.skill_id)}: {self.skill_name}, {self.damage}"
    
    def to_log_data(self):
        return f"{round(time.time() * 1000)}|{self.used_by}|{self.target}|{self.skill_name}|{self.damage}|{int(self.flag.crit)}|{int(self.flag.add_hit)}"
    
    @staticmethod
    def parse(content):
        # Extract used_by hex and advance content
        used_by_hex = content[None:8].hex()
        content = content[8:None]
        
        # Extract target hex and advance content
        target_hex = content[None:8].hex()
        content = content[8:None]
        
        # Extract skill_name_length and advance content
        skill_name_length = int.from_bytes(content[None:4], byteorder='little')
        content = content[4:None]
        
        # Extract and decode skill_name
        skill_name = ''
        try:
            skill_name = content[None:skill_name_length].decode('utf-16le')
        except:
            skill_name = content[None:skill_name_length].hex()
        content = content[skill_name_length:None]
        
        # Extract damage and advance content
        damage = int.from_bytes(content[None:4], byteorder='little')
        content = content[4:None]
        
        # Extract unknown_null and advance content
        unknown_null = content[None:12]
        content = content[12:None]
        
        # Debug print unknown_null if it's not all zeros
        if unknown_null != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
            if DEBUG:
                print(unknown_null.hex())
        
        # Extract flag bytes and advance content
        flag_bytes = content[None:20]
        content = content[20:None]
        
        # Extract skill_id and advance content
        skill_id = int.from_bytes(content[None:4], byteorder='little')
        content = content[4:None]
        
        # Create DamageFlag instance
        damage_flag = DamagePacket.DamageFlag()
        
        # Parse flags from flag_bytes
        flag_check(skill_name, flag_bytes, 0, 16)
        flag_check(skill_name, flag_bytes, 0, 32)
        
        damage_flag.first_hit = (flag_bytes[0] & 64) != 0
        damage_flag.default_attack = (flag_bytes[0] & 128) != 0
        damage_flag.crit = (flag_bytes[0] & 1) != 0
        
        flag_check(skill_name, flag_bytes, 0, 2)
        
        damage_flag.unguarded = (flag_bytes[0] & 4) != 0
        damage_flag.broken = (flag_bytes[0] & 8) != 0
        
        flag_check(skill_name, flag_bytes, 1, 16)
        flag_check(skill_name, flag_bytes, 1, 32)
        flag_check(skill_name, flag_bytes, 1, 64)
        
        temp_var = (flag_bytes[1] & 128) != 0
        damage_flag.multi_hit = (flag_bytes[1] & 1) != 0
        damage_flag.power_hit = (flag_bytes[1] & 2) != 0
        damage_flag.flurry_hit = (flag_bytes[1] & 4) != 0
        damage_flag.dot = (flag_bytes[1] & 8) != 0
        
        flag_check(skill_name, flag_bytes, 2, 16)
        flag_check(skill_name, flag_bytes, 2, 32)
        flag_check(skill_name, flag_bytes, 2, 64)
        flag_check(skill_name, flag_bytes, 2, 128)
        
        temp_var = (flag_bytes[2] & 1) != 0
        
        flag_check(skill_name, flag_bytes, 2, 2)
        flag_check(skill_name, flag_bytes, 2, 4)
        flag_check(skill_name, flag_bytes, 2, 8)
        
        damage_flag.bleed = (flag_bytes[3] & 16) != 0
        damage_flag.dark = (flag_bytes[3] & 32) != 0
        damage_flag.fire = (flag_bytes[3] & 64) != 0
        damage_flag.holy = (flag_bytes[3] & 128) != 0
        
        flag_check(skill_name, flag_bytes, 3, 1)
        
        temp_var = (flag_bytes[3] & 2) != 0
        
        flag_check(skill_name, flag_bytes, 3, 4)
        
        damage_flag.add_hit = (flag_bytes[3] & 8) != 0
        
        # Check additional flags in flag_bytes[4]
        temp_var = (flag_bytes[4] & 16) != 0
        temp_var = (flag_bytes[4] & 32) != 0
        temp_var = (flag_bytes[4] & 64) != 0
        temp_var = (flag_bytes[4] & 128) != 0
        
        damage_flag.ice = (flag_bytes[4] & 1) != 0
        damage_flag.electric = (flag_bytes[4] & 2) != 0
        damage_flag.poison = (flag_bytes[4] & 4) != 0
        damage_flag.mind = (flag_bytes[4] & 8) != 0
        
        # Handle skill name based on conditions
        if not skill_name or skill_name == 'Idle':
            if not skill_name:
                if damage_flag.dot:
                    skill_name = 'DOT_'
                else:
                    skill_name = 'UNKNOWN_'
            
            if damage_flag.holy:
                skill_name += 'HOLY'
            elif damage_flag.ice:
                skill_name += 'ICE'
            
            if damage_flag.fire:
                skill_name += 'FIRE'
            if damage_flag.electric:
                skill_name += 'ELECTRIC'
            if damage_flag.bleed:
                skill_name += 'BLEED'
            if damage_flag.poison:
                skill_name += 'POISON'
            if damage_flag.mind:
                skill_name += 'MIND'
            if damage_flag.dark:
                skill_name += 'DARK'
        
        return DamagePacket(used_by_hex, target_hex, skill_name_length, skill_name, damage, unknown_null, skill_id, damage_flag, flag_bytes.hex())