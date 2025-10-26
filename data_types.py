"""
Data type definitions for memory scanning.
Defines sizes, struct formats, and value ranges for different numeric types.
"""

import struct

class DataType:
    """Represents a data type for memory scanning."""
    
    def __init__(self, name: str, size: int, struct_code: str, min_val: int = None, max_val: int = None, is_signed: bool = True):
        self.name = name
        self.size = size
        self.struct_code = struct_code
        self.min_val = min_val
        self.max_val = max_val
        self.is_signed = is_signed
    
    def pack(self, value):
        """Pack a value into bytes."""
        return struct.pack(self.struct_code, value)
    
    def unpack(self, data: bytes):
        """Unpack bytes into a value."""
        return struct.unpack(self.struct_code, data)[0]


# Define available data types
DATA_TYPES = {
    '1': DataType('int8', 1, '<b', min_val=-128, max_val=127, is_signed=True),
    '2': DataType('int16', 2, '<h', min_val=-32768, max_val=32767, is_signed=True),
    '3': DataType('int32', 4, '<i', min_val=-2147483648, max_val=2147483647, is_signed=True),
    '4': DataType('int64', 8, '<q', min_val=-9223372036854775808, max_val=9223372036854775807, is_signed=True),
    '5': DataType('float', 4, '<f', is_signed=False),
    '6': DataType('double', 8, '<d', is_signed=False),
}

# Alias for the default type
INT32 = DATA_TYPES['3']


def get_data_type(choice: str) -> DataType:
    """Get a data type by user choice."""
    return DATA_TYPES.get(choice, INT32)


def format_hex_address(address: int) -> str:
    """Format an address as hexadecimal."""
    return f"0x{address:016X}"


def parse_value(value_str: str, data_type: DataType) -> int or float:
    """Parse a user input value according to the data type."""
    try:
        if data_type.name in ('float', 'double'):
            return float(value_str)
        else:
            return int(value_str)
    except ValueError:
        raise ValueError(f"Invalid {data_type.name} value: {value_str}")

