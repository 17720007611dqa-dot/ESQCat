cmake_minimum_required(VERSION 3.16)
project(ESQCat LANGUAGES CXX)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 OLD)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)

add_executable(esqcat
  src/main.cpp
  src/CloudServer.cpp
  src/CryptoUtils.cpp
  src/DataLoader.cpp
  src/GSpanMiner.cpp
  src/IndexBuilder.cpp)
target_include_directories(esqcat PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  ${Boost_INCLUDE_DIRS})
target_link_libraries(esqcat PRIVATE OpenSSL::Crypto)

if(MSVC)
  set_source_files_properties(src/GSpanMiner.cpp PROPERTIES COMPILE_OPTIONS /O2)
else()
  set_source_files_properties(src/GSpanMiner.cpp PROPERTIES COMPILE_OPTIONS -O3)
endif()
