/*
 * l2tp.h
 *
 *  Created on: Jan 30, 2018
 *      Author: cicerali
 */

#ifndef L2TP_H_
#define L2TP_H_

#include <stdint.h>
#include <errno.h>

#define L2TP_PORT 1701
#define BIND_ADDRESS "10.254.141.205"
//#define BIND_ADDRESS "10.254.157.50"
#define BUFFER_SIZE UINT16_MAX //65536
int init_udp(void);


#endif /* L2TP_H_ */
