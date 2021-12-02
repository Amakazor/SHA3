using System;
using System.Collections.Generic;

namespace Amakazor.Security.Hashing.SHA3
{
    internal static class ByteExtension
    {
        private static readonly Dictionary<byte, byte> ByteReversingLookupTable = new Dictionary<byte, byte>();
        internal static byte Reverse(this byte input)
        {
            if (ByteReversingLookupTable.ContainsKey(input))
                return ByteReversingLookupTable[input];

            byte result = 0x00;

            for (byte mask = 0x80; Convert.ToInt32(mask) > 0; mask >>= 1)
            {
                result = (byte)(result >> 1);

                if ((byte)(input & mask) != 0x00)
                   result = (byte)(result | 0x80);
            }

            ByteReversingLookupTable[input] = result;
            return result;
        }
    }
}
