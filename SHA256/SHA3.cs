using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Collections;

namespace Amakazor.Security.Hashing.SHA3
{
    public struct PreviewData
    {
        public PreviewData(bool preview, bool pause, bool previewMapping)
        {
            Preview = preview;
            Pause = pause;
            PreviewMapping = previewMapping;
        }

        public bool Preview { get; set; }
        public bool PreviewMapping { get; set; }
        public bool Pause { get; set; }
    }

    public static class SHA3
    {
        private static void Preview(PreviewData previewData, string message, string data = "")
        {
            if (previewData.Preview)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(message);
                Console.ForegroundColor = ConsoleColor.White;

                if (data.Length > 0)
                {
                    Console.WriteLine(data);
                }
                Console.WriteLine();
            }

            if (previewData.Preview && previewData.Pause)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Press any key to continue...");
                Console.ForegroundColor = ConsoleColor.White;
                Console.ReadKey();
                Console.WriteLine();
            }
        }

        private static readonly Dictionary<byte, byte> XMapping = new Dictionary<byte, byte>
        {
            {3,0}, {4,1}, {0,2}, {1,3}, {2,4}
        };
        
        private static readonly Dictionary<byte, byte> YMapping = new Dictionary<byte, byte>
        {
            {2,0}, {1,1}, {0,2}, {4,3}, {3,4}
        };

        public static string SHA224(string message, PreviewData previewData)
        {
            return SHA3Base(message, previewData, 224);
        }

        public static string SHA256(string message, PreviewData previewData)
        {
            return SHA3Base(message, previewData, 256);
        }
        
        public static string SHA384(string message, PreviewData previewData)
        {
            return SHA3Base(message, previewData, 384);
        }
        
        public static string SHA512(string message, PreviewData previewData)
        {
            return SHA3Base(message, previewData, 512);
        }

        private static string SHA3Base(string message, PreviewData previewData, int outputLength)
        {
            Preview(previewData, "String to hash:", message);
            BitArray bits = StringToBitArray(message);
            Preview(previewData, "String to hash as hex:", BitArrayToHexString(bits));
            bits.Length += 2;

            bits[bits.Length - 2] = false;
            bits[bits.Length - 1] = true;

            BitArray bitsToReturn = Sponge(1600 - outputLength * 2, outputLength * 2, bits, previewData);

            return BitArrayToHexString(bitsToReturn);
        }

        private static BitArray Sponge(int r, int capacity, BitArray N, PreviewData previewData)
        {
            int b = 1600;
            int d = capacity / 2;

            //1. Let P = N || pad(r, len(N)).
            BitArray Padding = Pad101((uint)r, (uint)N.Length);
            BitArray P = new BitArray(N);
            P.Length += Padding.Length;
            for (int i = 0; i < Padding.Length; i++) 
            {
                P[i + N.Length] = Padding[i];
            }

            Preview(previewData, "Padded input string:", BitArrayToHexString(P));

            //2.Let n = len(P) / r.
            int n = P.Length / r;

            Preview(previewData, "Segments to hash: ", n.ToString());

            //3. Let c = b - r.
            int c = b - r;

            //4. Let P0, ... , Pn-1 be the unique sequence of strings of length r such that P = P0 || ... || Pn-1.
            List<BitArray> PN = new List<BitArray>(n);
            for(int i = 0; i < n; i++)
            {
                PN.Add(new BitArray(r));
                for(int j = 0; j < r; j++)
                {
                    PN[i][j] = P[i * r + j];
                }

                Preview(previewData, "Segment number " + i + ": ", BitArrayToHexString(PN[i]));
            }

            //5. Let S = 0^b
            BitArray S = new BitArray(b);

            Preview(previewData, "Starting absorbtion phase of the sponge algorithm...");
            //6. For i from 0 to n-1, let S = f (S ⊕ (Pi || 0^c)).
            for (int i = 0; i < n; i++)
            {
                Preview(previewData, "State of the sponge construction: ", BitArrayToHexString(S));
                BitArray PNI = new BitArray(PN[i]);
                PNI.Length += c;

                Preview(previewData, "Starting absorbion of segment number " + i + ": ", BitArrayToHexString(PN[i]));
                S = Keccak1600(S.Xor(PNI), previewData);
                Preview(previewData, "Finished absorbion of segment number " + i + ".");
            }
            Preview(previewData, "Finished absorbtion phase of the sponge algorithm.");
            Preview(previewData, "Final state of the sponge construction: ", BitArrayToHexString(S));

            //7. Let Z be the empty string.
            BitArray Z = new BitArray(0);
            Preview(previewData, "Starting squeezing phase of the sponge algorithm...");

            while (true)
            {
                Preview(previewData, "Starting a round of squeezing...");
                Preview(previewData, "State of the return construction: ", BitArrayToHexString(Z));

                //8. Let Z = Z || Trunc r (S). 
                BitArray TruncatedS = new BitArray(S);
                TruncatedS.Length = r;

                int origininalZLength = Z.Length;
                Z.Length += r;
                for (int i = 0; i < r; i++)
                {
                    Z[origininalZLength + i] = TruncatedS[i];
                }
                Preview(previewData, "Return construction after truncating: ", BitArrayToHexString(Z));

                //9. If d ≤ |Z|, then return Trunc d (Z); else continue.
                if (d <= Z.Length)
                {
                    Preview(previewData, "Finished a round of squeezing.");
                    Preview(previewData, "Finished squeezing phase of the sponge algorithm.");
                    Preview(previewData, "Final state of the return construction: ", BitArrayToHexString(Z));
                    Z.Length = d;
                    Preview(previewData, "Truncated result: ", BitArrayToHexString(Z));
                    return Z;
                }

                //10. Let S = f(S), and continue with Step 8.
                Preview(previewData, "Hashing the return construction: ", BitArrayToHexString(Z));
                S = Keccak1600(S, previewData);
                Preview(previewData, "Return construction after hashing: ", BitArrayToHexString(Z));
                Preview(previewData, "Finished a round of squeezing.");
            }
        }

        private static BitArray Pad101(uint x, uint m)
        {
            int j = (int)((-m - 2) % x);

            if (j < 0) j = (int)x + j;

            BitArray toReturn = new BitArray(j);
            toReturn.Length += 2;
            toReturn.ShiftRight(1);
            toReturn[toReturn.Length - 1] = true;
            toReturn[0] = true;

            return toReturn;
        }

        private static BitArray Keccak1600(BitArray message, PreviewData previewData)
        {
            const int numberOfRounds = 24;

            List<List<BitArray>> state = BitArrayToState(message);

            for (int i = 0; i < numberOfRounds; i++)
            {
                Preview(previewData, "Starting hashing round " + i + "...");
                state = Round(state, i, previewData);
                Preview(previewData, "State of temporary sponge construction at the end of hashing round " + i + ": ", BitArrayToHexString(StateToBitArray(state)));
            }

            return StateToBitArray(state);
        }
        private static List<List<BitArray>> Round(List<List<BitArray>> state, int roundIndex, PreviewData previewData)
        {
            return ι(χ(π(ρ(θ(state, previewData), previewData), previewData), previewData), roundIndex, previewData);
        }
        private static List<List<BitArray>> θ(List<List<BitArray>> state, PreviewData previewData)
        {
            List<BitArray> C = PrepareEmptySubresult();
            for (byte x = 0; x < 5; x++)
            {
                for (byte z = 0; z < 64; z++)
                {
                    C[x][z] = XOR(state[XMapping[x]][YMapping[0]][z], XOR(state[XMapping[x]][YMapping[1]][z], XOR(state[XMapping[x]][YMapping[2]][z], XOR(state[XMapping[x]][YMapping[3]][z], state[XMapping[x]][YMapping[4]][z]))));
                }
            }

            List<BitArray> D = PrepareEmptySubresult();
            for (byte x = 0; x < 5; x++)
            {
                for (byte z = 0; z < 64; z++)
                {
                    D[x][z] = XOR(C[(x - 1) % 5 >= 0 ? (x - 1) % 5 : 5 + (x - 1) % 5][z], C[(x + 1) % 5][(z - 1) % 64 >= 0 ? (z - 1) % 64 : 64 + (z - 1) % 64]);
                }
            }

            List<List<BitArray>> result = PrepareEmptyResult();
            for (byte x = 0; x < 5; x++)
            {
                for (byte y = 0; y < 5; y++)
                {
                    for (byte z = 0; z < 64; z++)
                    {
                        result[XMapping[x]][YMapping[y]][z] = XOR(state[XMapping[x]][YMapping[y]][z], D[x][z]);
                    }
                }
            }

            if (previewData.PreviewMapping)
            {
                Preview(previewData, "State of temporary sponge construction after THETA: ", BitArrayToHexString(StateToBitArray(result)));
            }

            return result;
        }
        private static List<List<BitArray>> ρ(List<List<BitArray>> state, PreviewData previewData)
        {
            List<List<BitArray>> result = PrepareEmptyResult();

            for (byte z = 0; z < 64; z++)
            {
                result[0][0][z] = state[0][0][z];
            }

            byte x;
            byte y;
            (x, y) = (1, 0);

            var test = new Dictionary<(int, int), int>();

            for(byte t = 0; t <= 23; t++)
            {
                for (byte z = 0; z < 64; z++)
                {
                    int index = Mod((z - (t + 1) * (t + 2) / 2), 64);

                    if (z==0)
                    {
                        test.Add((x, y), Mod((z - (t + 1) * (t + 2) / 2), 64));
                    }

                    result[x][y][z] = state[x][y][index];
                }
                (x, y) = (y, (byte)Mod(2 * x + 3 * y, 5));
            }

            if (previewData.PreviewMapping)
            {
                Preview(previewData, "State of temporary sponge construction after RHO: ", BitArrayToHexString(StateToBitArray(result)));
            }

            return result;
        }

        private static List<List<BitArray>> π(List<List<BitArray>> state, PreviewData previewData)
        {
            List<List<BitArray>> result = PrepareEmptyResult();

            for (byte x = 0; x < 5; x++)
            {
                for (byte y = 0; y < 5; y++)
                {
                    for (byte z = 0; z < 64; z++)
                    {
                        result[x][y][z] = state[(byte)(Mod((x + (3 * y)), 5))][x][z];
                    }
                }
            }

            if (previewData.PreviewMapping)
            {
                Preview(previewData, "State of temporary sponge construction after PI: ", BitArrayToHexString(StateToBitArray(result)));
            }

            return result;
        }

        private static List<List<BitArray>> χ(List<List<BitArray>> state, PreviewData previewData)
        {
            List<List<BitArray>> result = PrepareEmptyResult();

            for (byte x = 0; x < 5; x++)
            {
                for (byte y = 0; y < 5; y++)
                {
                    for (byte z = 0; z < 64; z++)
                    {
                        result[XMapping[x]][YMapping[y]][z] = XOR(state[XMapping[x]][YMapping[y]][z], (XOR(state[XMapping[(byte)((x + 1) % 5)]][YMapping[y]][z], true) && state[XMapping[(byte)((x + 2) % 5)]][YMapping[y]][z]));
                    }
                }
            }

            if (previewData.PreviewMapping)
            {
                Preview(previewData, "State of temporary sponge construction after CHI: ", BitArrayToHexString(StateToBitArray(result)));
            }

            return result;
        }

        private static List<List<BitArray>> ι(List<List<BitArray>> state, int roundIndex, PreviewData previewData)
        {
            List<List<BitArray>> result = PrepareEmptyResult();

            for (byte x = 0; x < 5; x++)
            {
                for (byte y = 0; y < 5; y++)
                {
                    for (byte z = 0; z < 64; z++)
                    {
                        result[x][y][z] = state[x][y][z];
                    }
                }
            }

            BitArray RC = new BitArray(64);
            for (int j = 0; j <= 6; j++)
            {
                RC[(int)(Math.Pow(2, j) - 1)] = rc(j + 7 * roundIndex);
            }

            if (previewData.PreviewMapping)
            {
                Preview(previewData, "Round constant prepared for IOTA with round number "+ roundIndex +": ", BitArrayToHexString(RC));
            }

            for (int z = 0; z < 64; z++)
            {
                result[0][0][z] = XOR(result[0][0][z], RC[z]);
            }

            if (previewData.PreviewMapping)
            {
                Preview(previewData, "State of temporary sponge construction after IOTA: ", BitArrayToHexString(StateToBitArray(result)));
            }

            return result;
        }

        private static bool rc(int t)
        {
            if (t % 255 == 0) return true;

            BitArray R = new BitArray(new bool[] { true, false, false, false, false, false, false, false });
            for (int i = 1; i <= Mod(t, 255); i++)
            {
                R.Length += 1;
                R = R.ShiftRight(1);
                R[0] = XOR(R[0], R[8]);
                R[4] = XOR(R[4], R[8]);
                R[5] = XOR(R[5], R[8]);
                R[6] = XOR(R[6], R[8]);
                R.Length -= 1;
            }
            return R[0];
        }

        private static bool XOR (bool a, bool b)
        {
            return (a || b) && !(a && b);
        }

        private static List<List<BitArray>> PrepareEmptyResult()
        {
            return new List<List<BitArray>> { 
                new List<BitArray> { 
                    new BitArray(64), 
                    new BitArray(64), 
                    new BitArray(64), 
                    new BitArray(64), 
                    new BitArray(64) 
                },
                new List<BitArray> {
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64)
                },
                new List<BitArray> {
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64)
                },
                new List<BitArray> {
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64)
                },
                new List<BitArray> {
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64),
                    new BitArray(64)
                },
            };
        }

        private static List<BitArray> PrepareEmptySubresult()
        {
            return new List<BitArray>
            {
                new BitArray(64),
                new BitArray(64),
                new BitArray(64),
                new BitArray(64),
                new BitArray(64)
            };
        }

        private static BitArray StateToBitArray(List<List<BitArray>> state)
        {
            BitArray bitArray = new BitArray(1600);

            for (byte y = 0; y < 5; y++)
            {
                for (byte x = 0; x < 5; x++)
                {
                    for (byte z = 0; z < 64; z++)
                    {
                        bitArray[z + x * 64 + y * 320] = state[x][y][z];
                    }
                }
            }

            return bitArray;
        }

        private static List<List<BitArray>> BitArrayToState(BitArray message)
        {
            List<List<BitArray>> state = PrepareEmptyResult();

            for (byte y = 0; y < 5; y++)
            {
                for (byte x = 0; x < 5; x++)
                {
                    for (byte z = 0; z < 64; z++)
                    {
                        state[x][y][z] = message[z + x * 64 + y * 320];
                    }
                }
            }

            return state;
        }

        private static BitArray StringToBitArray(string message)
        {
            return new BitArray(Encoding.UTF8.GetBytes(message).Select(b => b).ToArray());
        }

        private static string BitArrayToHexString(BitArray bitArray)
        {
            byte[] bytes = new byte[bitArray.Length / 8];
            for (int i = 0; i < bitArray.Length / 8; i++)
            {
                byte hexByte = 0;
                for (int j = 7; j >= 0; j--)
                {
                    hexByte |= (byte)(bitArray[i * 8 + j] ? 1 : 0);
                    if (j > 0) hexByte <<= 1;
                }

                bytes[i] = hexByte;
            }

            return BitConverter.ToString(bytes).Replace("-", " ");
        }

        private static int Mod(int x, int m)
        {
            return (x % m + m) % m;
        }
    }
}
