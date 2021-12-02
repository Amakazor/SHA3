using System.Collections;

namespace Amakazor.Security.Hashing.SHA3
{
    internal static class BitArrayExtension
    {
        internal static BitArray ShiftRight(this BitArray input, int amount)
        {
            BitArray toReturn = new BitArray(input.Length);
            for (int i = 0; i < toReturn.Length - amount; i++)
            {
                toReturn[i + amount] = input[i];
            }
            return toReturn;
        }
    }
}
