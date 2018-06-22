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

            //a public key for testing in Hex
            const string Alicebase16strpubX = "0x14CC3B7FBEF441E21DE27CA72F5E2BB60EFEA474A5973028589016D36DB11E267A1F49FD2DC1F42553E0A6BB4E66CA9E8C2667074A7EABAD1A10545626B53F4ECC9";
            const string Alicebase16strY = "0x190E33894B32DD6FDFDF8E560630B2419CC45A7FF770530CD564354A5D4D7E76DB1F4A1C0DC9E7D5720F257C5A8D2D908C342217300ACD78D258D00EEDDB2C441F5";
            const string curve = "P-521";//"SECP521R1";
            const string Algorithm = "ECDH";


            X9ECParameters ecP = NistNamedCurves.GetByName(curve);

            FpCurve c = (FpCurve)ecP.Curve;

            ECFieldElement x = c.FromBigInteger(new BigInteger(System.Numerics.BigInteger.Parse(Alicebase16strpubX, NumberStyles.HexNumber).ToString()));
            ECFieldElement y = c.FromBigInteger(new BigInteger(System.Numerics.BigInteger.Parse(Alicebase16strY, NumberStyles.HexNumber).ToString()));

            Org.BouncyCastle.Math.EC.ECPoint q = new FpPoint(c, x, y);
            ECPublicKeyParameters xxpk = new ECPublicKeyParameters("ECDH", q, SecObjectIdentifiers.SecP521r1);

            IAsymmetricCipherKeyPairGenerator KeyGen = GeneratorUtilities.GetKeyPairGenerator(Algorithm);
            KeyGenerationParameters keygenParams = new ECKeyGenerationParameters(new ECDomainParameters(ecP.Curve, ecP.G, ecP.N), new SecureRandom());

            KeyGen.Init(keygenParams);
            //DHParameters bobParameters = aliceGenerator.GenerateParameters();

            AsymmetricCipherKeyPair KeyPair = KeyGen.GenerateKeyPair();
            IBasicAgreement KeyAgree = AgreementUtilities.GetBasicAgreement(Algorithm);
            KeyAgree.Init(KeyPair.Private);
            //END SETUP BOB

            ECPublicKeyParameters params2 = (ECPublicKeyParameters)KeyPair.Public;

            Console.WriteLine("PublicKeyX Base(16): " + params2.Q.XCoord.ToBigInteger().ToString(16).ToUpper());
            Console.WriteLine("PublicKeyY Base(16): " + params2.Q.YCoord.ToBigInteger().ToString(16).ToUpper());

            //BigInteger aliceAgree = aliceKeyAgree.CalculateAgreement(bobKeyPair.Public);
            BigInteger Agree = KeyAgree.CalculateAgreement(xxpk);
            Console.WriteLine("Shared Secrect Base(16):" + Agree.ToString(16).ToUpper());

            string ciphertext = Encryption.EncryptString("Test", Agree.ToByteArray()); //last 32 bytes key //16 bytes IV
            Console.WriteLine("Ciphertext: " + ciphertext);

            string cleartext = Encryption.DecryptString(ciphertext, Agree.ToByteArray());
            Console.WriteLine("Cleartext: " + cleartext);

        }
    }

}
  