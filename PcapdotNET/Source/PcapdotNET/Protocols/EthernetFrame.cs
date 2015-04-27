namespace PcapdotNET.Protocols
{
    public class EthernetFrame
    {
        private readonly int[] _destinationIp = new int[6];
        private readonly int[] _sourceIp = new int[6];

        public EthernetFrame(int[] _DestinationIP, int[] _SourceIP)
        {
            _destinationIp = _DestinationIP;
            _sourceIp = _SourceIP;
        }

        public string GetDestinationIP()
        {
            string result = _destinationIp[0] + "." + _destinationIp[1] + "." + _destinationIp[2] + "." + _destinationIp[3] +
                            "." + _destinationIp[4] + "." + _destinationIp[5];
            return result;
        }

        public string GetSourceIP()
        {
            string result = _sourceIp[0] + "." + _sourceIp[1] + "." + _sourceIp[2] + "." + _sourceIp[3] + "." + _sourceIp[4] +
                            "." + _sourceIp[5];
            return result;
        }

        public string GetInformation()
        {
            return _destinationIp[0].ToString("X") + "." + _destinationIp[1].ToString("X") + "." +
                   _destinationIp[2].ToString("X") + "." + _destinationIp[3].ToString("X") +
                   "." + _destinationIp[4].ToString("X") + "." + _destinationIp[5].ToString("X") + " <- " +
                   _sourceIp[0].ToString("X") + "." + _sourceIp[1].ToString("X") + "." + _sourceIp[2].ToString("X") + "." +
                   _sourceIp[3].ToString("X") + "." + _sourceIp[4].ToString("X") +
                   "." + _sourceIp[5].ToString("X");
        }
    }
}