#include "fault_tolerance.h"
int error_count;
void erro_start()
{
	if (error_count > 10)
	{
		error_count = 0;
	}
}
void erro_add()
{
	error_count++;
}
int erro_get()
{
	return error_count;
}
