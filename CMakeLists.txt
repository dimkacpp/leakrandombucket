cmake_minimum_required(VERSION 3.5)

project(shaping LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SYSLIBPREFIX /usr/lib/x86_64-linux-gnu)

AUX_SOURCE_DIRECTORY(./src mainsrc)
list(REMOVE_ITEM mainsrc "./src/main.cpp")

include_directories("./include")

AUX_SOURCE_DIRECTORY(./test testdir)

FILE(GLOB_RECURSE INC_ALL "./include/*.h*")
FILE(GLOB_RECURSE INC_ALLH "./include/*.h")

find_package( Boost REQUIRED COMPONENTS system thread program_options)

find_path(BOOST_INCLUDE_DIR boost)
include_directories(${BOOST_INCLUDE_DIR})

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)


SET(CMAKE_CXX_FLAGS "${CXX_FLAGS} -g -pthread -march=nehalem -DBUFFCNT=10000 -DMTU=1500 -DBOOST_TEST_NO_LIB  -DCRCOPT -DBOOST_ASIO_DISABLE_HANDLER_TYPE_REQUIREMENTS=1 -std=c++14")

add_executable(shaping ${mainsrc} ${INC_ALL} ${INC_ALLH} "./src/main.cpp")
add_executable(test_all ${INC_ALL} ${INC_COM} ${INC_ALLH} ${testdir} ${mainsrc})

add_library( pcap STATIC IMPORTED )
set_target_properties( pcap PROPERTIES IMPORTED_LOCATION ${SYSLIBPREFIX}/libpcap.a )


target_link_libraries(shaping Boost::program_options Boost::thread  Boost::system pcap)
target_link_libraries(test_all Boost::program_options Boost::thread  Boost::system pcap )
