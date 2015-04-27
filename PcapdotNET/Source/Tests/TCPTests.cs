using System;
using NUnit.Framework;
using PcapdotNET.Protocols;

namespace Tests
{
    [TestFixture]
    public class TestTCPFrameParse
    {
        [Test]
        public void NoFileTest()
        {
            var T = new FileParser("D:/icmp fragmented.cap");
            Console.WriteLine(T.GetTCPFrameList().Capacity);

            foreach (TCPandUDPFrame Element in T.GetTCPFrameList())
            {
                Console.WriteLine(Element.GetInformation());
            }
        }
    }
}