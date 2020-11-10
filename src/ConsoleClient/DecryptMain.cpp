#include <RC5.hpp>
#include <argparse/argparse.hpp>
#include <limits>
#include <fstream>

std::streamsize getSize(std::istream &in) {
  in.ignore(std::numeric_limits<std::streamsize>::max());
  std::streamsize size = in.gcount();
  in.clear();
  in.seekg(0, std::ios_base::beg);
  return size;
}

bool decrypt(std::istream &in, std::ostream &out, const std::string& password) {
  using RC5Type = rc5::RC5_CBC<std::uint16_t, 12, 16, rc5::Type::Pad>;//TODO
  
  RC5Type algorithm = RC5Type({1,2,3,4,5}, {});
  auto inSize = getSize(in);
  std::cout << inSize;
  if (!(inSize % RC5Type::BLOCK_SIZE) && inSize >= RC5Type::BLOCK_SIZE)
    algorithm.setRealEncryptedTextSize(inSize);
  else
    return false;
  constexpr std::streamsize BUFFER_SIZE = RC5Type::BLOCK_SIZE * 20;
  do {
    std::vector<rc5::Byte> inBuffer(BUFFER_SIZE);
    in.read(reinterpret_cast<char *>(inBuffer.data()), BUFFER_SIZE);
    inBuffer.resize(in.gcount());
    std::vector<rc5::Byte> outBuffer;
    algorithm.decrypt(inBuffer, outBuffer);
    out.write(reinterpret_cast<char *>(outBuffer.data()), outBuffer.size());
  }
  while(in);
  return true;
}

int main(int argc, const char *argv[]) {
  argparse::ArgumentParser argumentParser("RC5CBCPad_16_12_16_Decrytor");
  argumentParser.add_argument("input").help("will be decrypted");
  argumentParser.add_argument("password").help("will be used as password");
  argumentParser.add_argument("output").help("output file path");
  try {
    argumentParser.parse_args(argc, argv);
  } catch (const std::runtime_error &error) {
    std::cerr << error.what() << '\n';
    std::cerr << argumentParser;
    exit(0);
  }
  
  auto input = argumentParser.get<std::string>("input");
  auto password = argumentParser.get<std::string>("password");
  auto output = argumentParser.get<std::string>("output");
  std::ifstream inFs(input, std::ios::binary);
  if (!inFs.good()) {
    std::cerr << "Failed to read file: " << input << '\n';
    exit(0);
  }
  std::ofstream outFs(output, std::ios::binary | std::ios::out);
  if (!outFs.good()) {
    std::cerr << "Failed to write file: " << input << '\n';
    exit(0);
  }
  if (!decrypt(inFs, outFs, password))
    std::cerr << "Decryption failed!";
}

