using System.Globalization;

namespace PcapdotNET.Protocols
{
    // TCPandUDPFrame - contains information about processed frame (UDP & TCP files)
    public class TCPandUDPFrame
    {
        private readonly int[] _destinationIp = new int[4];  //4 parts of IP address
        private readonly uint _destinationPort;              //2 bytes for the destination port number
        private readonly uint _frameLength;                  //4 bytes for frame length
        private readonly uint _protocolNumber;               //2 bytes for the source port number
        private readonly int[] _sourceIp = new int[4];       //4 parts for source ip
        private readonly uint _sourcePort;                   //2 bytes for the source port number
        private readonly TableProtocols _tableProtocol = new TableProtocols();

        public TCPandUDPFrame(int[] destinationIP, uint destinationPort, uint frameLength, int[] sourceIP,
            uint sourcePort,uint protocolNumber)
        {
            _destinationIp = destinationIP;
            _destinationPort = destinationPort;
            _frameLength = frameLength;
            _sourceIp = sourceIP;
            _sourcePort = sourcePort;
            _protocolNumber = protocolNumber;
        }

        public string GetInformation()
        {
            return "\n###########\n" + _sourceIp[0] + "." + _sourceIp[1] + "." + _sourceIp[2] + "." + _sourceIp[3] + ":" + _sourcePort + " -> " +
                   _destinationIp[0] + "." + _destinationIp[1] + "." + _destinationIp[2] + "." + _destinationIp[3] + ":" +
                   _destinationPort + "\n" + "FrameLength : " + _frameLength + "\n" + "Protocol: " + GetProtocolName();
        }


        public string GetProtocolName()
        {
            return _tableProtocol.GetProtocol((int)_protocolNumber);
        }

        public string GetFrameLength()
        {
            return _frameLength.ToString();
        }

        public string GetDestinationIP()
        {
            string result = _destinationIp[0] + "." + _destinationIp[1] + "." + _destinationIp[2] + "." + _destinationIp[3];
            return result;
        }

        public string GetSourceIP()
        {
            string result = _sourceIp[0] + "." + _sourceIp[1] + "." + _sourceIp[2] + "." + _sourceIp[3];
            return result;
        }

        public string GetSourcePort()
        {
            return _sourcePort.ToString(CultureInfo.InvariantCulture);
        }

        public string GetDestinationPort()
        {
            return _destinationPort.ToString();
        }
    }
}