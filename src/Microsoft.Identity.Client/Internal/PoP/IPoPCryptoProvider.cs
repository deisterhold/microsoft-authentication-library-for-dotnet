using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity.Client.Internal.PoP
{
    public interface IPoPCryptoProvider
    {
        string KeyId { get; }
        
        string Algorithm { get; }

        //string JWK { get;  }

        string CreateJwkClaim();

        byte[] Sign(byte[] payload);
    }
}
