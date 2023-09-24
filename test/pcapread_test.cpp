#include "pcapread_test.h"

#include <boost/test/unit_test.hpp>
#include "pcapreader.h"
#include "randpool.h"

using namespace sim;

BOOST_AUTO_TEST_SUITE(MAINTOOL)


BOOST_AUTO_TEST_CASE( read_pcap )
{
  using namespace sim;

  sim::RandPool randpool;
  sim::PcapReader pcap_reader;

  bool reslt = pcap_reader.processFile("wrong.pcap", "final.pcap", randpool, 0.5);

  BOOST_TEST( !reslt );
}

BOOST_AUTO_TEST_SUITE_END()
