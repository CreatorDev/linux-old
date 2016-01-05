#ifndef SPI_NOR_COMMON_H
#define SPI_NOR_COMMON_H

int spi_nor_wait_till_ready(struct spi_nor *nor);
int spi_nor_lock_and_prep(struct spi_nor *nor, enum spi_nor_ops ops);
void spi_nor_unlock_and_unprep(struct spi_nor *nor, enum spi_nor_ops ops);

#endif
