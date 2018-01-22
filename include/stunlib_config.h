/*
 *  See license file
 */

#ifndef STUNLIB_STUNLIB_CONFIG_H
#define STUNLIB_STUNLIB_CONFIG_H

/*
 * Various configuration options for STUN that can be changed
 */

/*** STUN decode helpers ***/

#define STUN_MSG_ID_SIZE                 12

#define STUN_MSG_MAX_REALM_LENGTH        128
#define STUN_MSG_MAX_NONCE_LENGTH        128
#define STUN_MSG_MAX_USERNAME_LENGTH     255
#define STUN_MSG_MAX_PASSWORD_LENGTH     255
#define STUN_MIN_CHANNEL_ID              0x4000
#define STUN_MAX_CHANNEL_ID              0x7FFF

#define IPV4_ADDR_LEN                    16
#define IPV4_ADDR_LEN_WITH_PORT          (IPV4_ADDR_LEN + 6) /* Need extra space
                                                              * for :port */
#define IPV6_ADDR_LEN                    100

#define STUN_REQ_TRANSPORT_UDP         (uint32_t)17 /* IANA protocol number */

#define STUN_MIN_PACKET_SIZE             20
#define STUN_HEADER_SIZE                 20
#define STUN_MAX_PACKET_SIZE            1556
#define STUN_MAX_ATTR_SIZE              1500
#define STUN_MAX_STRING                 256
#define STUN_MAX_UNKNOWN_ATTRIBUTES       8
#define STUN_MAGIC_COOKIE_ARRAY         {0x21, 0x12, 0xA4, 0x42}
#define STUN_MAGIC_COOKIE_SIZE          4
#define STUN_PACKET_MASK                0xC0
#define STUN_PACKET                     0x00
#define TURN_CHANNEL_PACKET             0x40
#define STUN_STRING_ALLIGNMENT          4

#define STUNCLIENT_MAX_RETRANSMITS          9
#define STUNCLIENT_RETRANSMIT_TIMEOUT_LIST      100, 200, 300, 400, 500, 500, \
  500, 500, 500                                                                              /*
                                                                                              *
                                                                                              *
                                                                                              *
                                                                                              *
                                                                                              *
                                                                                              *
                                                                                              *msec
                                                                                              **/
#define STUNCLIENT_DFLT_TICK_TIMER_MS            50

#define STUN_KEEPALIVE_TIMER_SEC    15

#define TURN_SEND_IND_HDR_SIZE      36  /* fixed overhead when using  TURN send
                                         * indication  */
/* hdr(20)+Cookie(8)+Vers(8)+Data(4) */
#define TURN_INTEG_LEN              24  /* size of integrity attribute */
#define TURN_CHANNEL_DATA_HDR_SIZE   4  /* overhead when using  TURN channel
                                         * data     */

#define STUN_MAX_PEER_ADDR          10 /* max no. of peer addresses supported
                                        * (e.g. when encoding  CreatePermission)
                                        **/

#define STUN_DFLT_PAD ' '             /* default padding char */

#define STUN_MAX_TRANSACTIONS  60
#define STUN_SOFTWARE_NAME "Cisco"

#endif //STUNLIB_STUNLIB_CONFIG_H
