#pragma once
#include <Windows.h>
#include <vector>

//Original Casual class by P47TR!CK marche seulement qu'il y a une vtable
inline void**& getvtable(void* inst, size_t offset = 0)
{
	return *reinterpret_cast<void***>((size_t)inst + offset);
}
inline const void** getvtable(const void* inst, size_t offset = 0)
{
	return *reinterpret_cast<const void***>((size_t)inst + offset);
}
template< typename Fn >
inline Fn getvfunc(const void* inst, size_t index, size_t offset = 0)
{
	return reinterpret_cast<Fn>(getvtable(inst, offset)[index]);
}


class CHookHandler
{

public:
	inline void* detour(void *targetFunction, void *newFunction)
	{
#ifdef DEBUG		
		CDetouHook temp;


		void *ret = temp.detourHook((byte*)targetFunction, (byte*)newFunction);
		hooklist.push_back(temp);
#else
		CDetouHook temp;
		void *ret = temp.detourHook((byte*)targetFunction, (byte*)newFunction);
#endif
		return ret;
	}

	inline void unhookall()//todo handle destruction de pointeur
	{
		for (unsigned int i = 0; i < hooklist.size(); i++)
			hooklist.at(i).unhook();
	}

private:


	class CDetouHook //todo utiliser byte* à la place de char* car char n'est pas adapté vu qu'il va que jusqu'à la moitié de unsigned char 
	{
	public:

		void* detourHook(byte *targetFunction, byte *newFunction); //1byte = 8 bits donc dans un byte on peut mettre 0xe9 


		bool unhook();

	private:
		//note très important d'utiliser char* comme ça quand on fair par ex originaladdress+1 ça ajoute vraiment 1 à l'adresse et pas 4(ou une autre valeur) comme ça peut le faire en faisaint de l'arithmétique de pointeur
							  //pt un to do: handle les registres pour remettre tous les registres aux anciennes valeurs quand j'appelle l'original
		enum//to do supprimer les commentaires du hook et les laisser dans le projet recherche et mettre que si je veux les commentaires je peux aller là 
		{
			OP_JUMP = 0xE9,
			OP_SUB = 0x81, //liste à completer... ac mov etc //aussi il y a plusieurs opcode pour sub et mov etc... //il y a aussi des opcodes ou il faut plusieurs byte pour determiner l'instruction....
			OP_SUB2 = 0x83,//ceci est faux ça depend du deuxieme bytes mais il faut que je change de technique ma nouvelle idée est de ne rien faire tant que je n'ai pas trouvé un opcode "connu" que je peux hook
			OP_TEST = 0xF7, //ceci aussi est faux il faut vraiment penser à changer de technique
		};



		inline const int determineLength(byte *targetFunction);

		inline void insertjumpataddress(byte *targetAddress, byte *newAddress)
		{
			DWORD relativeAddr = newAddress - targetAddress - 5;  //le -5 c'est car c'est la taille de l'instruction jmp plus le "paramètre" càd la taille de"jmp addr"
			*targetAddress = OP_JUMP;
			*(DWORD*)((DWORD)targetAddress + 1) = relativeAddr; //obligé de cast à dword pour que ce soit 4  bytes
		}



		int m_length;
		byte *m_originabytesladdress;
		byte *m_targetfuncaddress;
	};



	std::vector<CDetouHook> hooklist;
};


void modify_call_instruction(void* address_where_to_modify_the_call, void* new_address);