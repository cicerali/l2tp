/*
 * test.h
 *
 *  Created on: Feb 23, 2018
 *      Author: cicerali
 */

#ifndef TEST_H_
#define TEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <log.h>

#include <parser.h>
#include <test.h>

void test_l2tp();
void make_header(l2tp_control_message *message);
void test_sccrq(l2tp_control_message * message);
void test_sccrp(l2tp_control_message * message);
void test_scccn(l2tp_control_message * message);
void test_stopccn(l2tp_control_message * message);
void test_hello(l2tp_control_message * message);
void test_icrq(l2tp_control_message * message);
void test_iccp(l2tp_control_message * message);
void test_iccn(l2tp_control_message * message);
void test_ocrq(l2tp_control_message * message);
void test_ocrp(l2tp_control_message * message);
void test_occn(l2tp_control_message * message);
void test_cdn(l2tp_control_message * message);
void test_wen(l2tp_control_message * message);
void test_sli(l2tp_control_message * message);
void test_zlb(l2tp_control_message * message);
void send_receive(l2tp_control_message * message);


#endif /* TEST_H_ */
