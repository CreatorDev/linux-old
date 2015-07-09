#ifndef __IMG_FWLDR
#define __IMG_FWLDR 1

void fwldr_init(unsigned char *core_addr, unsigned char *gram_addr,
		unsigned char *gram_b4_addr);
void fwldr_stop_thrd(unsigned int tno);
void fwldr_soft_reset(unsigned int tno);
int fwldr_load_fw(const unsigned char *fw_data);

#endif
