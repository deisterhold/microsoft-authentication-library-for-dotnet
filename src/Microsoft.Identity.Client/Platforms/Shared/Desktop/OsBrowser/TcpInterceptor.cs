﻿    // Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Identity.Client.Platforms.Shared.Desktop.OsBrowser
{
    /// <summary>
    /// This object is responsible for listening to a single TCP request, on localhost:port, 
    /// extracting the uri, parsing 
    /// </summary>
    /// <remarks>
    /// The underlying TCP listener might capture multiple requests, but only the first one is handled.
    /// </remarks>
    internal class TcpInterceptor : ITcpInterceptor
    {
        private readonly Core.ICoreLogger _logger;

        public TcpInterceptor(Core.ICoreLogger logger)
        {
            _logger = logger;
        }

        public async Task<Uri> ListenToSingleRequestAndRespondAsync(
            int port,
            Func<Uri, string> responseProducer,
            CancellationToken cancellationToken)
        {
            TcpListener tcpListener = null;
            TcpClient tcpClient = null;

            try
            {
                tcpListener = new TcpListener(IPAddress.Loopback, port);

                tcpClient =
                    await AcceptTcpClientAsync(tcpListener, cancellationToken)
                    .ConfigureAwait(false);

                return await ExtractUriAndRespondAsync(tcpClient, responseProducer, cancellationToken)
                    .ConfigureAwait(false);

            }
            finally
            {
                tcpListener.Stop();

#if DESKTOP || NET_CORE
                tcpClient?.Close();
#else
                tcpClient?.Dispose();
#endif
            }
        }

        /// <summary>
        /// AcceptTcpClientAsync does not natively support cancellation, so use this wrapper. Make sure
        /// the cancellation token is registered to stop the listener.
        /// </summary>
        /// <remarks>See https://stackoverflow.com/questions/19220957/tcplistener-how-to-stop-listening-while-awaiting-accepttcpclientasync</remarks>
        private static async Task<TcpClient> AcceptTcpClientAsync(TcpListener listener, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            using (ct.Register(listener.Stop))
            {
                try
                {
                    listener.Start();
                    return await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                }
                catch (SocketException e) when (e.SocketErrorCode == SocketError.Interrupted)
                {
                    throw new OperationCanceledException(ct);
                }
                catch (ObjectDisposedException) when (ct.IsCancellationRequested)
                {
                    throw new OperationCanceledException(ct);
                }
                // thrown when cancellation is requested before the call to listen
                catch (InvalidOperationException) when (ct.IsCancellationRequested)
                {
                    throw new OperationCanceledException(ct);
                }
            }
        }

        private async Task<Uri> ExtractUriAndRespondAsync(
            TcpClient tcpClient,
            Func<Uri, string> responseProducer,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string httpRequest = await GetTcpResponseAsync(tcpClient, cancellationToken).ConfigureAwait(false);
            Uri uri = HttpResponseParser.ExtractUriFromHttpRequest(httpRequest, _logger);

            // write an "OK, please close the browser message" 
            await WriteResponseAsync(responseProducer(uri), tcpClient.GetStream(), cancellationToken)
                .ConfigureAwait(false);

            return uri;
        }

        private static async Task<string> GetTcpResponseAsync(TcpClient client, CancellationToken cancellationToken)
        {
            NetworkStream networkStream = client.GetStream();

            byte[] readBuffer = new byte[1024];
            StringBuilder stringBuilder = new StringBuilder();

            // Incoming message may be larger than the buffer size. 
            do
            {
                int numberOfBytesRead = await networkStream.ReadAsync(readBuffer, 0, readBuffer.Length, cancellationToken)
                    .ConfigureAwait(false);

                string s = Encoding.ASCII.GetString(readBuffer, 0, numberOfBytesRead);
                stringBuilder.Append(s);

            }
            while (networkStream.DataAvailable);

            return stringBuilder.ToString();
        }

        private async Task WriteResponseAsync(
            string message,
            NetworkStream stream,
            CancellationToken cancellationToken)
        {
            var response = Encoding.ASCII.GetBytes(message);
            await stream.WriteAsync(response, 0, response.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

    }
}
