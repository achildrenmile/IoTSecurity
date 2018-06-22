using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X509;
using System.Diagnostics;
using Org.BouncyCastle.OpenSsl;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Pkcs;
using System.Globalization;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Math.EC;

namespace IFX.ECCDHTest
{
    class Program
    {


        static void Main(string[] args)
        {
            //TestMethod();
            ECDHKeyExchangeExample();
            Console.Read();
        }

        public static void ECDHKeyExchangeExample()
        {
            /*NOTE: this should represent an example of ECDH. As there are no mechanisms used in order to ensure if Alice is Alice and Bob is Bob as now
             * certificate is used in this example. */

            /* Define used key exchange algorithm. In our case this is elliptic curve diffie hellmann. */
            const string Algorithm = "ECDH";

            /* ALICE starts the key exchange. She sends the the X and Y coordinates of her public key as well as the used curve to BOB */

            const string Alicebase16strpubX = "0x14CC3B7FBEF441E21DE27CA72F5E2BB60EFEA474A5973028589016D36DB11E267A1F49FD2DC1F42553E0A6BB4E66CA9E8C2667074A7EABAD1A10545626B53F4ECC9";
            const string Alicebase16strY = "0x190E33894B32DD6FDFDF8E560630B2419CC45A7FF770530CD564354A5D4D7E76DB1F4A1C0DC9E7D5720F257C5A8D2D908C342217300ACD78D258D00EEDDB2C441F5";
            const string curve = "P-521";//"SECP521R1";

            /****************************************************************************/
            /* BOB starts the actions. Bob uses the public public key coordinates as well as the curve to generate an ephemeral key
               pair on his side.
            */

            X9ECParameters ecP = NistNamedCurves.GetByName(curve);

            FpCurve c = (FpCurve)ecP.Curve;

            ECFieldElement x = c.FromBigInteger(new BigInteger(System.Numerics.BigInteger.Parse(Alicebase16strpubX, NumberStyles.HexNumber).ToString()));
            ECFieldElement y = c.FromBigInteger(new BigInteger(System.Numerics.BigInteger.Parse(Alicebase16strY, NumberStyles.HexNumber).ToString()));

            Org.BouncyCastle.Math.EC.ECPoint q = new FpPoint(c, x, y);
            ECPublicKeyParameters xxpk = new ECPublicKeyParameters("ECDH", q, SecObjectIdentifiers.SecP521r1);

            IAsymmetricCipherKeyPairGenerator KeyGen = GeneratorUtilities.GetKeyPairGenerator(Algorithm);
            KeyGenerationParameters keygenParams = new ECKeyGenerationParameters(new ECDomainParameters(ecP.Curve, ecP.G, ecP.N), new SecureRandom());

            KeyGen.Init(keygenParams);

            AsymmetricCipherKeyPair KeyPair = KeyGen.GenerateKeyPair();
            IBasicAgreement KeyAgree = AgreementUtilities.GetBasicAgreement(Algorithm);
            /*****************************************************************************/

            /* BOB calculates the SHARED SECRET */
            KeyAgree.Init(KeyPair.Private);
            BigInteger Agree = KeyAgree.CalculateAgreement(xxpk);
            /*****************************************************************************/

            /*BOB encrypts his secret message. Using the Encryption helper method with AES 256 CBC. The helper method is using the last
            16 bytes of the generated secret and a generated initial vector of 16 byte to encrypt*/
            string ciphertext = Encryption.EncryptString("Hallo Alice, this is an important message to you.", Agree.ToByteArray());
            ECPublicKeyParameters params2 = (ECPublicKeyParameters)KeyPair.Public;
            /*****************************************************************************/

            /*BOB is sending the x and y coordinates of his public key and the encrypted message to Alice on a public (not secured) channel*/
            Console.WriteLine("PublicKeyX Base(16): " + params2.Q.XCoord.ToBigInteger().ToString(16).ToUpper());
            Console.WriteLine("PublicKeyY Base(16): " + params2.Q.YCoord.ToBigInteger().ToString(16).ToUpper());
            Console.WriteLine("Ciphertext: " + ciphertext);
            /*****************************************************************************/

        }
    }

}
