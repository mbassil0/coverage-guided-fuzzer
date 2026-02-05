#pragma once
struct model_t
{

};

class CModelLoader
{
public:
	model_t * GetModelForName(const char *name, int referencetype)
	{
		typedef model_t*(__thiscall* OriginalFn)(void*, const char*, int);
		return getvfunc<OriginalFn>(this, 7)(this, name, referencetype);
	}


};
