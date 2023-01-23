#include "HelperFunctions.h"
#include "json.hpp"

using json = nlohmann::json;
std::unique_ptr<MemMan> memoryManager = std::make_unique<MemMan>();

struct Packet
{
	std::string name;
	int id;
	uintptr_t address;
	std::string signature;
};

void generate_output(std::vector<Packet> signatures)
{
	std::ofstream file;
	file.open("opcodes.h");

	file << "#pargma once\n";
	file << "#include <Windows.h>\n";
	file << "namespace opcodes\n";
	file << "{\n";

	for (auto s : signatures)
	{
		file << "    DWORD64 " << s.name << " = 0x" << std::uppercase << std::hex << s.id << ";\n";
	}

	file << "\n}\n";
	file.close();
}

std::vector<Packet> parse_signatures(json& data, MODULEENTRY32 mod)
{
	std::vector<Packet> parsedSigs;
	json signatures = data["signatures"];

	for (int id = 0; id < signatures.size(); id++)
	{
		std::string name = signatures[id]["name"];
		int opcode = signatures[id]["opcode"];
		std::string sig = signatures[id]["signature"];
		
		DWORD64 address = HelperFunctions::FindPatternExModule(memoryManager->handle, L"ffxiv_dx11.exe", sig.c_str(), mod);
		
		parsedSigs.push_back({ name, opcode, address, sig });
	}
	return parsedSigs;
}

std::vector<Packet> parse_jumptable(DWORD64 imageBase, DWORD64 jumptableOffset, int jumptableSize)
{
	std::vector<Packet> parsedJumptable;
	
	std::string name = "fromJumptable";

	for (int id = 0; id < jumptableSize; id++)
	{
		DWORD64 address = imageBase + (id * 4) + jumptableOffset;
		auto a = memoryManager->readMem<DWORD>(address) + imageBase;
		parsedJumptable.push_back({ name, id, (uintptr_t)a, ""});
	}
	return parsedJumptable;
}

int main()
{
	DWORD64 gameProc = memoryManager->getProcess(L"ffxiv_dx11.exe");
	auto mod = HelperFunctions::GetModule(gameProc, L"ffxiv_dx11.exe");

	std::cout << "proc: " << gameProc << "\n";
	std::cout << "Base address: 0x" << std::hex << (DWORD64)mod.modBaseAddr << "\n";

	std::ifstream f("jump_signatures.json");
	auto data = json::parse(f);

	std::string jumptableSig = data["jumptable_signature"];
	DWORD64 address = HelperFunctions::FindPatternExModule(memoryManager->handle, L"ffxiv_dx11.exe", jumptableSig.c_str(), mod);
	int jumptableOffset = memoryManager->readMem<int>(address + data["jumptable_offset"]);
	int jumptableSize = memoryManager->readMem<int>(address + data["jumptable_size"]);

	std::cout << "jumptable index address: 0x" << std::hex << address << "\n";
	std::cout << "jumptable offset: 0x" << std::hex << jumptableOffset << "\n";
	std::cout << "jumptable size: 0x" << std::hex << jumptableSize << std::endl;

	auto signatures = parse_signatures(data, mod);
	auto jumptable = parse_jumptable((DWORD64)mod.modBaseAddr, jumptableOffset, jumptableSize);

	std::vector<Packet> packets;


	/**
	* TODO:
	* implement propper logic
	* implement checks for new opcodes
	* implement checks for changes
	**/
	for (int i = 0; i < jumptableSize; i++)
	{
		for (int j = 0; j < signatures.size(); j++)
		{
			if (jumptable[i].address == signatures[j].address)
			{
				if ((jumptable[i].id != signatures[j].id) && (signatures[j].id != -1))
				{
					std::cout << signatures[j].name << " changed; old: " << signatures[j].id << " => new: " << jumptable[i].id << "\n";
				}

				packets.push_back(
					{
						signatures[j].name,
						jumptable[i].id,
						jumptable[i].address,
						signatures[j].signature
					}
				);

				break;
			}
		}
	}
	generate_output(packets);

	return 0;
}