trait BytesTrait<T> {
    fn from_le_bytes(bytes: Span<u8>) -> T;
    fn to_le_bytes(value: T) -> Span<u8>;
}

pub impl U16BytesImpl of BytesTrait<u16> {
    fn from_le_bytes(mut bytes: Span<u8>) -> u16 {
        // Ensure we have exactly 2 bytes
        assert(bytes.len() == 2, 'Invalid byte array length');

        // Get the bytes in little-endian order
        let byte0 = *bytes.pop_front().unwrap(); // Least significant byte
        let byte1 = *bytes.pop_front().unwrap(); // Most significant byte

        // Combine bytes using bitwise operations
        // byte0 is shifted 0 positions (LSB)
        // byte1 is shifted 8 positions left (MSB)
        let result = byte0.into() + (byte1.into() * 256);

        result
    }

    fn to_le_bytes(value: u16) -> Span<u8> {
        let mut bytes = ArrayTrait::new();

        // Extract least significant byte (byte0)
        // value % 256 gives us the lower 8 bits
        let byte0: u8 = (value % 256).try_into().unwrap();
        bytes.append(byte0);

        // Extract most significant byte (byte1)
        // value / 256 gives us the upper 8 bits
        let byte1: u8 = ((value / 256) % 256).try_into().unwrap();
        bytes.append(byte1);

        bytes.span()
    }
}

pub impl U32BytesImpl of BytesTrait<u32> {
    fn from_le_bytes(mut bytes: Span<u8>) -> u32 {
        assert(bytes.len() == 4, 'Invalid byte array length');

        let byte0: u32 = (*bytes.at(0)).into();
        let byte1: u32 = (*bytes.at(1)).into() * 0x100;
        let byte2: u32 = (*bytes.at(2)).into() * 0x10000;
        let byte3: u32 = (*bytes.at(3)).into() * 0x1000000;

        byte0 + byte1 + byte2 + byte3
    }

    fn to_le_bytes(value: u32) -> Span<u8> {
        let mut bytes = ArrayTrait::new();

        bytes.append((value % 0x100).try_into().unwrap());
        bytes.append(((value / 0x100) % 0x100).try_into().unwrap());
        bytes.append(((value / 0x10000) % 0x100).try_into().unwrap());
        bytes.append(((value / 0x1000000) % 0x100).try_into().unwrap());

        bytes.span()
    }
}


pub impl U64BytesImpl of BytesTrait<u64> {
    fn from_le_bytes(mut bytes: Span<u8>) -> u64 {
        assert(bytes.len() == 8, 'Invalid byte array length');

        let byte0: u64 = (*bytes.at(0)).into();
        let byte1: u64 = (*bytes.at(1)).into() * 0x100;
        let byte2: u64 = (*bytes.at(2)).into() * 0x10000;
        let byte3: u64 = (*bytes.at(3)).into() * 0x1000000;
        let byte4: u64 = (*bytes.at(4)).into() * 0x100000000;
        let byte5: u64 = (*bytes.at(5)).into() * 0x10000000000;
        let byte6: u64 = (*bytes.at(6)).into() * 0x1000000000000;
        let byte7: u64 = (*bytes.at(7)).into() * 0x100000000000000;

        byte0 + byte1 + byte2 + byte3 + byte4 + byte5 + byte6 + byte7
    }

    fn to_le_bytes(value: u64) -> Span<u8> {
        let mut bytes = ArrayTrait::new();

        bytes.append((value % 0x100).try_into().unwrap());
        bytes.append(((value / 0x100) % 0x100).try_into().unwrap());
        bytes.append(((value / 0x10000) % 0x100).try_into().unwrap());
        bytes.append(((value / 0x1000000) % 0x100).try_into().unwrap());
        bytes.append(((value / 0x100000000) % 0x100).try_into().unwrap());
        bytes.append(((value / 0x10000000000) % 0x100).try_into().unwrap());
        bytes.append(((value / 0x1000000000000) % 0x100).try_into().unwrap());
        bytes.append(((value / 0x100000000000000) % 0x100).try_into().unwrap());

        bytes.span()
    }
}
