#include "detour_hooks.h"


const int CHookHandler::CDetouHook::determineLength(byte *targetFunction) //à completer... //aussi si je mets char* targetfunction en param ça crash je devrais comprendre pq mais bon pas le temps
{
	/*on détermine la longueur qui est de 5bytes minimum puis après on fait attention à ne pas écrire au milieu d'une instruction*/
	int ret = 5;

	/*for (int i = 0; i < 5; i++)//afficher les opcode sur ida puis ça devient plus facile de voir directement le size d'une instruction
	{
		switch (*(targetFunction + i)) //je ne devrais pas commencer à 0 pcq je pense que ça commence tjr par push ebp mais bon pas sûr je reverserai d'autre fonctions plus tard peut etre
		{
		case OP_SUB:
			ret = i + 6;
			break;

		case OP_SUB2:
			ret = i + 3;
			break;

		case OP_TEST:
			ret = i + 10;
			break;

		case 0x8B:
			ret = i + 6;
			break;

		}
	}*/
	ret = 6; //fixed size because it wasn't needed in my case to determine it dynamically for a general case it should be detemrined dynamically!
	ret = 7;
	return ret;
}




void* CHookHandler::CDetouHook::detourHook(byte *targetFunction, byte *newFunction) //1byte = 8 bits donc dans un byte on peut mettre 0xe9 
{
	/*on utilise le mode debug seulemlent quand je developpe pour le jeu et veut accelerer dans mon developement et  reload le cheat sans devoir restart le jeu donc j'unhook les fonctions, sinon pas besoin d'unhook en temps normal
	dans cette fonction il y a des etapes supplementaires*/
	DWORD old;
	const int length = determineLength((byte*)targetFunction);

	byte *originalFirstBytesWithJump = new byte[length + 5]; //have to allocate dynamically because length isn't directly a constant value such as 4 or 2  //pour pouvoir mettres les originaux plus 5 pour le jump après 
	memcpy(originalFirstBytesWithJump, targetFunction, length);


	if (!VirtualProtect(targetFunction, 5, PAGE_EXECUTE_READWRITE, &old))//on donne les permissions suffisantes pour changer les bytes de la fonction d'origine sinon on a un Access violation
		return nullptr;

	insertjumpataddress(targetFunction, newFunction);

	if (!VirtualProtect(targetFunction, 5, old, &old))
		return nullptr;

	//FlushInstructionCache(GetCurrentProcess(), p, length + 5);
	if (!VirtualProtect((void*)originalFirstBytesWithJump, length + 5, PAGE_EXECUTE_READWRITE, &old))
		return nullptr;

	insertjumpataddress(originalFirstBytesWithJump + length, targetFunction + length);


	m_length = length;
	m_targetfuncaddress = targetFunction;
	m_originabytesladdress = originalFirstBytesWithJump;


	return originalFirstBytesWithJump;
}//GetLastError()





bool CHookHandler::CDetouHook::unhook()
{
	DWORD old;
	if (!VirtualProtect(m_targetfuncaddress, m_length, PAGE_EXECUTE_READWRITE, &old))//on donne les permissions suffisantes pour changer les bytes de la fonction d'origine sinon on a un Access violation
		return false;

	memcpy(m_targetfuncaddress, m_originabytesladdress, m_length);//ond oit juste remettre les 5 premier aussi tuer les originaux çaserait bien

	if (!VirtualProtect(m_targetfuncaddress, m_length, PAGE_EXECUTE_READWRITE, &old))//on donne les permissions suffisantes pour changer les bytes de la fonction d'origine sinon on a un Access violation
		return false;


	delete[] m_originabytesladdress;//todo voir si ça supprime bien dans un debuggeur
	return true;
}



void modify_call_instruction(void* address_where_to_modify_the_call, void* new_address)
{
	/*
	quand on a une instruction "call a" modify_call_instruction fait en sorte
	qu'on "call b" a la place de "call a"   (b etant le prametre new_address)

	note suppose qu'on est en 32bit
	*/

	DWORD old;
	if (!VirtualProtect((void*)address_where_to_modify_the_call, 5, PAGE_EXECUTE_READWRITE, &old))
	{
		printf("modify_call_instruction: virtualprotect failed \n");
		return;
	}

	if (*(byte*)address_where_to_modify_the_call != 0xE8)
	{
		printf("modify_call_instruction: address_where_to_modify_the_call isn't a call instruction it was a %p \n", *(byte*)address_where_to_modify_the_call);
		VirtualProtect((void*)address_where_to_modify_the_call, 5, old, &old);
		return;
	}

	int32_t relative_addr = (uint32_t)new_address - 5 - (uint32_t)address_where_to_modify_the_call;
	*(int32_t*)((byte*)address_where_to_modify_the_call + 1) = relative_addr;

	VirtualProtect((void*)address_where_to_modify_the_call, 5, old, &old);


}