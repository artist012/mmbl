from collections import OrderedDict

class CustomLRUCache:
    max_size: int
    data: OrderedDict
    
    def __init__(self, size):
        self.max_size = size
        self.data = OrderedDict()
    
    def __getitem__(self, key):
        if key in self.data:
            self.data.move_to_end(key)
            return self.data[key]
        return None
    
    def __setitem__(self, key, data):
        if not data:
            return None
        
        self.data[key] = data
        self.data.move_to_end(key)
        
        if len(self.data) > self.max_size:
            self.data.popitem(last=False)
        
        return None
    
    def __contains__(self, key):
        return key in self.data