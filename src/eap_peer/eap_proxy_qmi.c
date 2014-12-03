/*--------------------------------------------------------------------------
Copyright (c) 2013, The Linux Foundation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
--------------------------------------------------------------------------*/

#include "includes.h"
#include "common.h"
#include "eap_proxy_qmi.h"

#ifdef CONFIG_EAP_PROXY
#include "qmi_uim_srvc.h"
#include "qmi_client.h"
#include "qmi_idl_lib.h"
#include "user_identity_module_v01.h"
#include "eap_config.h"
#include "common/wpa_ctrl.h"
#include <cutils/properties.h>
#ifdef CONFIG_EAP_PROXY_MDM_DETECT
#include "mdm_detect.h"
#endif /* CONFIG_EAP_PROXY_MDM_DETECT */
#if defined(__BIONIC_FORTIFY)
#include <sys/system_properties.h>
#endif

#define IMSI_LENGTH 15
#define WPA_UIM_QMI_EVENT_MASK_CARD_STATUS        \
					(1 << QMI_UIM_EVENT_CARD_STATUS_BIT_V01)
#define WPA_UIM_QMI_EVENT_READ_TRANSPARENT_REQ    \
					(1 << QMI_UIM_READ_TRANSPARENT_REQ_V01)

/* Default timeout (in milli-seconds) for synchronous QMI message */
#define WPA_UIM_QMI_DEFAULT_TIMEOUT               5000

#define EAP_PROXY_PROPERTY_BASEBAND	"ro.baseband"
#ifdef CONFIG_EAP_PROXY_MSM8994_TARGET
#define EAP_PROXY_TARGET_PLATFORM	"ro.board.platform"
#endif /* CONFIG_EAP_PROXY_MSM8994_TARGET */
#if defined(__BIONIC_FORTIFY)
#define EAP_PROXY_PROPERTY_BASEBAND_SIZE   PROP_VALUE_MAX
#else
#define EAP_PROXY_PROPERTY_BASEBAND_SIZE   10
#endif
#define EAP_PROXY_BASEBAND_VALUE_MSM       "msm"
#define EAP_PROXY_BASEBAND_VALUE_APQ       "apq"
#define EAP_PROXY_BASEBAND_VALUE_SVLTE1    "svlte1"
#define EAP_PROXY_BASEBAND_VALUE_SVLTE2A   "svlte2a"
#define EAP_PROXY_BASEBAND_VALUE_SGLTE     "sglte"
#define EAP_PROXY_BASEBAND_VALUE_CSFB      "csfb"
#define EAP_PROXY_BASEBAND_VALUE_MDMUSB    "mdm"
#ifdef CONFIG_EAP_PROXY_MSM8994_TARGET
#define EAP_PROXY_TARGET_PLATFORM_MSM8994  "msm8994"
#endif /* CONFIG_EAP_PROXY_MSM8994_TARGET */
#define EAP_PROXY_TARGET_FUSION4_5_PCIE    "fusion4_5_pcie"
#define EAP_PROXY_BASEBAND_VALUE_UNDEFINED "undefined"

#ifdef SIM_AKA_IDENTITY_IMSI
typedef struct {
  uim_card_state_enum_v01			card_state;
  uim_card_error_code_enum_v01			card_error_code;
  u8						app_state;
  u8						app_type;
} wpa_uim_card_info_type;

typedef struct {
  int                                   card_ready_idx;
  wpa_uim_card_info_type                card_info[QMI_UIM_CARDS_MAX_V01];
  qmi_client_type                       qmi_uim_svc_client_ptr;
  int                                   qmi_msg_lib_handle;
} wpa_uim_struct_type;

/* Global variable with the card status */
wpa_uim_struct_type   wpa_uim[MAX_NO_OF_SIM_SUPPORTED];
#endif /* SIM_AKA_IDENTITY_IMSI */

static int eap_proxy_qmi_init_handle;
static qmi_client_type qmi_uim_svc_client_ptr;
#ifdef CONFIG_EAP_PROXY_DUAL_SIM
static int eap_auth_session_flag[MAX_NO_OF_SIM_SUPPORTED] = {FALSE, FALSE};
static Boolean qmi_uim_svc_client_initialized[MAX_NO_OF_SIM_SUPPORTED] = {FALSE, FALSE};
#else
static int eap_auth_session_flag[MAX_NO_OF_SIM_SUPPORTED] = {FALSE};
static Boolean qmi_uim_svc_client_initialized[MAX_NO_OF_SIM_SUPPORTED] = {FALSE};
#endif /* CONFIG_EAP_PROXY_DUAL_SIM */

static void eap_proxy_eapol_sm_set_bool(struct eap_proxy_sm *sm,
			 enum eapol_bool_var var, Boolean value);
static Boolean eap_proxy_eapol_sm_get_bool(struct eap_proxy_sm *sm,
					enum eapol_bool_var var);

/* Call-back function to process an authenticationr result indication from
 * QMI EAP service */
static void handle_qmi_eap_ind(int userHandle, qmi_service_id_type serviceId,
			void *userData, qmi_eap_indication_id_type indId,
					qmi_eap_indication_data_type *indData);

/* Call-back function to process an EAP response from QMI EAP service */
static void handle_qmi_eap_reply(int userHandle, qmi_service_id_type serviceId,
			int sysErrCode, int qmiErrCode, void *userData,
	qmi_eap_async_rsp_id_type rspId, qmi_eap_async_rsp_data_type *rspData);

static u8 *eap_proxy_getKey(struct eap_proxy_sm *eap_proxy);
static enum eap_proxy_status eap_proxy_qmi_response_wait(struct eap_proxy_sm *eap_proxy);
static int eap_proxy_is_state_changed(struct eap_proxy_sm *sm);
static enum eap_proxy_status eap_proxy_process(struct eap_proxy_sm  *eap_proxy,
					u8 *eapReqData, int eapReqDataLen, struct eap_sm *eap_sm);
static char bin_to_hexchar(u8 ch);

static void wpa_qmi_client_indication_cb
(
	qmi_client_type                user_handle,
	unsigned long                  msg_id,
	unsigned char                 *ind_buf_ptr,
	int                            ind_buf_len,
	void                          *ind_cb_data
);
static void dump_buff(u8 *buff, int len);
#ifdef CONFIG_CTRL_IFACE
static const char *eap_proxy_sm_state_txt(int state);
#endif /* CONFIG_CTRL_IFACE */
static Boolean eap_proxy_build_identity(struct eap_proxy_sm *eap_proxy, u8 id,
                                                 struct eap_sm *eap_sm);

#ifdef SIM_AKA_IDENTITY_IMSI
static char *imsi;
static int imsi_len_g = 0;
static int card_mnc_len = -1;
#ifdef CONFIG_EAP_PROXY_DUAL_SIM
static unsigned int slot = 0;
static unsigned int session_type;
#endif /* CONFIG_EAP_PROXY_DUAL_SIM */

static Boolean wpa_qmi_register_events(int sim_num);
static Boolean wpa_qmi_read_card_imsi(int sim_num);
static Boolean wpa_qmi_read_card_status(int sim_num);

#endif
#define EAP_SUB_TYPE_SIM_START     0x0a
#define EAP_SUB_TYPE_AKA_IDENTITY  0x05
#define EAP_RESP_TYPE_NAK             3

/* Call-back function to process QMI system events */
void handle_qmi_sys_events(qmi_sys_event_type  eventId,
const qmi_sys_event_info_type *eventInfo, void *userData)
{

/*  Based on the qmi sys events we need to update our qmi and eap states.*/
	wpa_printf(MSG_INFO, "handleQmiSysEvent\n");
	wpa_printf(MSG_INFO, "Event Id=%d;\n", eventId);
}

#ifdef SIM_AKA_IDENTITY_IMSI
static void wpa_qmi_client_indication_cb
(
	qmi_client_type                user_handle,
	unsigned long                  msg_id,
	unsigned char                 *ind_buf_ptr,
	int                            ind_buf_len,
	void                          *ind_cb_data
)
{
	/* we currently not need the card status changes */
	/* Making this a dummy CB handler */
}

static Boolean wpa_qmi_register_events(int sim_num)
{
	qmi_client_error_type               qmi_err_code      = 0;
	uim_get_card_status_resp_msg_v01   *qmi_response_ptr  = NULL;
	uim_event_reg_req_msg_v01           event_reg_params;

	qmi_response_ptr = (uim_get_card_status_resp_msg_v01 *)
			os_malloc(sizeof(uim_get_card_status_resp_msg_v01));
	if (qmi_response_ptr == NULL) {
		wpa_printf(MSG_ERROR,
			"Couldn't allocate memory for qmi_response_ptr\n");
		return FALSE;
	}

	/* Register for events first */
	os_memset(qmi_response_ptr, 0,
			sizeof(uim_get_card_status_resp_msg_v01));
	os_memset(&event_reg_params, 0, sizeof(uim_event_reg_req_msg_v01));

	event_reg_params.event_mask |= (WPA_UIM_QMI_EVENT_MASK_CARD_STATUS);

	qmi_err_code = qmi_client_send_msg_sync(wpa_uim[sim_num].qmi_uim_svc_client_ptr,
						QMI_UIM_EVENT_REG_REQ_V01,
						(void *) &event_reg_params,
						sizeof(uim_event_reg_req_msg_v01),
						(void *) qmi_response_ptr,
						sizeof(*qmi_response_ptr),
						WPA_UIM_QMI_DEFAULT_TIMEOUT);
	wpa_printf(MSG_ERROR, " QMI_UIM_EVENT_REG_REQ_V01, qmi_err_code: 0x%x\n",
				qmi_err_code);
	if (qmi_err_code != QMI_NO_ERR) {
		wpa_printf(MSG_ERROR,
			"Error for QMI_UIM_EVENT_REG_REQ_V01, qmi_err_code: 0x%x\n",
			qmi_err_code);
		os_free(qmi_response_ptr);
		qmi_response_ptr = NULL;
		return FALSE;
	}
	/* Free the allocated response buffer */
	if (qmi_response_ptr)
	{
		os_free(qmi_response_ptr);
		qmi_response_ptr = NULL;
	}

	if (wpa_qmi_read_card_status(sim_num))
		return TRUE;
	else {
		wpa_printf(MSG_ERROR,
				"Error while reading SIM card status\n");
		return FALSE;
	}
}

static Boolean wpa_qmi_read_card_status(int sim_num)
{
	unsigned int                        i = 0, j = 0;
	Boolean                             card_found = FALSE;
	qmi_client_error_type               qmi_err_code      = 0;
	uim_get_card_status_resp_msg_v01   *qmi_response_ptr  = NULL;

	wpa_printf (MSG_ERROR, "eap_proxy: reading card %d values\n", sim_num+1);
	qmi_response_ptr = (uim_get_card_status_resp_msg_v01 *)
		os_malloc(sizeof(uim_get_card_status_resp_msg_v01));
	if (qmi_response_ptr == NULL) {
		wpa_printf(MSG_ERROR,
			"Couldn't allocate memory for qmi_response_ptr !\n");
		return FALSE;
	}

	os_memset(qmi_response_ptr,
				0,
				sizeof(uim_get_card_status_resp_msg_v01));
	qmi_err_code = qmi_client_send_msg_sync(wpa_uim[sim_num].qmi_uim_svc_client_ptr,
						QMI_UIM_GET_CARD_STATUS_REQ_V01,
						NULL,
						0,
						(void *) qmi_response_ptr,
						sizeof(*qmi_response_ptr),
						WPA_UIM_QMI_DEFAULT_TIMEOUT);
	wpa_printf(MSG_ERROR,
				"QMI_UIM_GET_CARD_STATUS_REQ_V01, qmi_err_code: 0x%x\n",
				qmi_err_code);
	if (qmi_err_code != QMI_NO_ERR) {
		wpa_printf(MSG_ERROR,
			"Error for QMI_UIM_GET_CARD_STATUS_REQ_V01, qmi_err_code: 0x%x\n",
			qmi_err_code);
		os_free(qmi_response_ptr);
		qmi_response_ptr = NULL;
		return FALSE;
	}

	/* Updated global card status if needed */
	if (!qmi_response_ptr->card_status_valid ||
	  (qmi_response_ptr->resp.result != QMI_RESULT_SUCCESS_V01)) {
		wpa_printf(MSG_ERROR, "card_status is not valid !\n");
		os_free(qmi_response_ptr);
		qmi_response_ptr = NULL;
		return FALSE;
	}
	/* Update global in case of new card state or error code */
	i = sim_num;
	if ( i < QMI_UIM_CARDS_MAX_V01 &&
	     i < qmi_response_ptr->card_status.card_info_len ) {
		wpa_printf(MSG_ERROR, "card_info[i].card_state: 0x%x\n",
			qmi_response_ptr->card_status.card_info[i].card_state);
		wpa_printf(MSG_ERROR, "card_info[i].error_code: 0x%x\n",
			qmi_response_ptr->card_status.card_info[i].error_code);

		wpa_uim[sim_num].card_info[i].card_state =
			qmi_response_ptr->card_status.card_info[i].card_state;

		wpa_uim[sim_num].card_info[i].card_error_code =
			qmi_response_ptr->card_status.card_info[i].error_code;
#ifdef CONFIG_EAP_PROXY_DUAL_SIM
	    do {
		   if (qmi_response_ptr->card_status.index_gw_pri != 0xFFFF) {
			slot = (qmi_response_ptr->card_status.index_gw_pri & 0xFF00) >> 8;
			if (slot == i) {
			    session_type = QMI_UIM_SESSION_TYPE_PRI_GW_PROV;
			    wpa_printf (MSG_ERROR, "eap_proxy: read_card_status: prime slot = %d\n", slot);
			    break;
			}
		   }
		   if (qmi_response_ptr->card_status.index_gw_sec != 0xFFFF) {
			slot = (qmi_response_ptr->card_status.index_gw_sec & 0xFF00) >> 8;
			if (slot == i) {
			    session_type = QMI_UIM_SESSION_TYPE_SEC_GW_PROV;
			    wpa_printf (MSG_ERROR, "eap_proxy: read_card_status: second slot = %d\n", slot);
			    break;
			}
		   }
		   wpa_printf (MSG_ERROR, "eap_proxy: read_card_status: Not GW it's 1x\n");
		   return FALSE;
		}while(0);

		if (slot > 1){
			wpa_printf (MSG_ERROR, "eap_proxy: read_card_status: INVALID slot = %d and i = %d\n", slot, i);
			return FALSE;
		}
#endif /* CONFIG_EAP_PROXY_DUAL_SIM */

		if (qmi_response_ptr->card_status.card_info[i].card_state ==
			UIM_CARD_STATE_PRESENT_V01) {
			for (j = 0 ; j < QMI_UIM_APPS_MAX_V01 ; j++) {
				wpa_uim[sim_num].card_info[i].app_type =
					qmi_response_ptr->card_status.card_info[i].app_info[j].app_type;

				wpa_uim[sim_num].card_info[i].app_state =
					qmi_response_ptr->card_status.card_info[i].app_info[j].app_state;

				if (((qmi_response_ptr->card_status.card_info[i].app_info[j].app_type == 1) ||
				(qmi_response_ptr->card_status.card_info[i].app_info[j].app_type == 2)) &&
				(qmi_response_ptr->card_status.card_info[i].app_info[j].app_state ==
				UIM_APP_STATE_READY_V01)) {
					wpa_printf(MSG_ERROR, "card READY\n");
					wpa_printf(MSG_ERROR, "card_info[i].app_type : 0x%x\n",
					qmi_response_ptr->card_status.card_info[i].app_info[j].app_type);
					wpa_printf(MSG_ERROR, "card_info[i].app_state : 0x%x\n",
					qmi_response_ptr->card_status.card_info[i].app_info[j].app_state);
					card_found = TRUE;
					break;
				}
			}
		}

		if (card_found) {
			wpa_printf(MSG_ERROR, "card found for SIM = %d\n", sim_num+1);
		}
	}

	if ((!card_found) || (i ==QMI_UIM_CARDS_MAX_V01) ||
		(j == QMI_UIM_APPS_MAX_V01)) {
		if (qmi_response_ptr) {
			os_free(qmi_response_ptr);
			qmi_response_ptr = NULL;
		}
		wpa_printf(MSG_ERROR, "SIM/USIM not ready\n");
		return FALSE;
	}

	wpa_printf(MSG_ERROR, "SIM/USIM ready\n");
	wpa_uim[sim_num].card_ready_idx = i;

	/* Free the allocated response buffer */
	if (qmi_response_ptr) {
		os_free(qmi_response_ptr);
		wpa_printf(MSG_ERROR, "Free the allocated response buffer\n");
		qmi_response_ptr = NULL;
	}

	return TRUE;
} /* wpa_qmi_read_card_status */

static Boolean wpa_qmi_read_card_imsi(int sim_num)
{
	int			length;
	unsigned char           *data;
	int                     src = 0, dst = 0;
	Boolean                 card_found = FALSE,
	qmi_status = TRUE;
	qmi_client_error_type               qmi_err_code = 0;
	uim_read_transparent_req_msg_v01   *qmi_read_trans_req_ptr = NULL;
	uim_read_transparent_resp_msg_v01  *qmi_read_trans_resp_ptr = NULL;

	qmi_read_trans_req_ptr = (uim_read_transparent_req_msg_v01 *)
					os_malloc(sizeof(uim_read_transparent_req_msg_v01));
	if (qmi_read_trans_req_ptr == NULL) {
		wpa_printf(MSG_ERROR,
			"Couldn't allocate memory for qmi_read_trans_req_ptr !\n");
		return FALSE;
	}
	qmi_read_trans_resp_ptr = (uim_read_transparent_resp_msg_v01 *)
					os_malloc(sizeof(uim_read_transparent_resp_msg_v01));
	if (qmi_read_trans_resp_ptr == NULL) {
		wpa_printf(MSG_ERROR,
			"Couldn't allocate memory for qmi_read_trans_resp_ptr !\n");

		if (qmi_read_trans_req_ptr) {
			os_free(qmi_read_trans_req_ptr);
			qmi_read_trans_req_ptr = NULL;
		}
		return FALSE;
	}

	os_memset(qmi_read_trans_resp_ptr, 0,
			sizeof(uim_read_transparent_resp_msg_v01));
	os_memset(qmi_read_trans_req_ptr, 0,
			sizeof(uim_read_transparent_req_msg_v01));

	qmi_read_trans_req_ptr->read_transparent.length = 0;
	qmi_read_trans_req_ptr->read_transparent.offset = 0;
	qmi_read_trans_req_ptr->file_id.file_id = 0x6F07;
	qmi_read_trans_req_ptr->file_id.path_len = 4;

#ifdef CONFIG_EAP_PROXY_DUAL_SIM
	wpa_printf (MSG_ERROR, "eap_proxy: read_card_imsi: session_type = %d\n", session_type);
	qmi_read_trans_req_ptr->session_information.session_type = session_type;
#else
	qmi_read_trans_req_ptr->session_information.session_type =
				QMI_UIM_SESSION_TYPE_PRI_GW_PROV;
#endif /* CONFIG_EAP_PROXY_DUAL_SIM */
	qmi_read_trans_req_ptr->session_information.aid_len = 0;

	/* For USIM*/
	if ((wpa_uim[sim_num].card_info[wpa_uim[sim_num].card_ready_idx].app_type ==
		UIM_APP_TYPE_USIM_V01)) {
		qmi_read_trans_req_ptr->file_id.path[0] = 0x00;
		qmi_read_trans_req_ptr->file_id.path[1] = 0x3F;
		qmi_read_trans_req_ptr->file_id.path[2] = 0xFF;
		qmi_read_trans_req_ptr->file_id.path[3] = 0x7F;

	} else /* For SIM*/
	if ((wpa_uim[sim_num].card_info[wpa_uim[sim_num].card_ready_idx].app_type ==
		UIM_APP_TYPE_SIM_V01)) {
		qmi_read_trans_req_ptr->file_id.path[0] = 0x00;
		qmi_read_trans_req_ptr->file_id.path[1] = 0x3F;
		qmi_read_trans_req_ptr->file_id.path[2] = 0x20;
		qmi_read_trans_req_ptr->file_id.path[3] = 0x7F;
	}
	else {
		if (qmi_read_trans_req_ptr) {
			os_free(qmi_read_trans_req_ptr);
			qmi_read_trans_req_ptr = NULL;
		}
		if (qmi_read_trans_resp_ptr) {
			os_free(qmi_read_trans_resp_ptr);
			qmi_read_trans_resp_ptr = NULL;
		}
		return FALSE;
	}

	qmi_err_code = qmi_client_send_msg_sync(wpa_uim[sim_num].qmi_uim_svc_client_ptr,
					QMI_UIM_READ_TRANSPARENT_REQ_V01,
					(void *)qmi_read_trans_req_ptr,
					sizeof(*qmi_read_trans_req_ptr),
					(void *) qmi_read_trans_resp_ptr,
					sizeof(*qmi_read_trans_resp_ptr),
					WPA_UIM_QMI_DEFAULT_TIMEOUT);

	if (QMI_NO_ERR == qmi_err_code) {
		if (qmi_read_trans_resp_ptr->read_result_valid) {
			length  =
				qmi_read_trans_resp_ptr->read_result.content_len;
			data    =
				qmi_read_trans_resp_ptr->read_result.content;
				wpa_printf(MSG_ERROR,
					"IMSI SIM content length = %d\n",
					length);

			/* Received IMSI is in the 3GPP format
				converting it into ascii string */
			imsi = os_malloc((2 * length));
			os_memset(imsi, 0, (2 * length));
			for (src = 1, dst = 0;
				(src < length) && (dst < (length * 2));
				src++) {
				wpa_printf(MSG_ERROR,
					"IMSI read from SIM = %d src %d\n",
					data[src], src);
				if(data[src] == 0xFF) {
					break;
				}
				if (src > 1) {
					imsi[dst] = bin_to_hexchar(data[src] & 0x0F);
					dst++;
					wpa_printf(MSG_ERROR,
					"IMSI dst = %d dst %d\n",
					imsi[dst-1], dst);
				}
				/* Process upper part of byte for all bytes */
				imsi[dst] = bin_to_hexchar(data[src] >> 4);
				dst++;
				wpa_printf(MSG_ERROR,
					"IMSI dst = %d dst %d\n",
					imsi[dst-1], dst);
			}
				imsi_len_g = (data[0]*2 - 1); //dst;
				wpa_printf(MSG_ERROR,
					"IMSI first digit = %d read length = %d imsi %20s\n",
					data[0],imsi_len_g, imsi);
			} else{
				wpa_printf(MSG_ERROR,
					"IMSI read failure read_result_valid = %d\n",
					qmi_read_trans_resp_ptr->read_result_valid);
				qmi_status = FALSE;
			}
		} else {
			wpa_printf(MSG_ERROR,
					"Unable to read IMSI from UIM service qmi_err_code=%x\n",
					qmi_err_code);
			qmi_status = FALSE;
	}

	/* READ EF_AD */
	/* if qmi_status is FALSE, UIM read for mnc may not be required - To Do */
	qmi_read_trans_req_ptr->file_id.file_id = 0x6FAD;
	qmi_err_code = qmi_client_send_msg_sync(wpa_uim[sim_num].qmi_uim_svc_client_ptr,
					QMI_UIM_READ_TRANSPARENT_REQ_V01,
					(void *)qmi_read_trans_req_ptr,
					sizeof(*qmi_read_trans_req_ptr),
					(void *) qmi_read_trans_resp_ptr,
					sizeof(*qmi_read_trans_resp_ptr),
					WPA_UIM_QMI_DEFAULT_TIMEOUT);
	if (QMI_NO_ERR == qmi_err_code) {
		if (qmi_read_trans_resp_ptr->read_result_valid) {
			length  =
				qmi_read_trans_resp_ptr->read_result.content_len;
			data    =
				qmi_read_trans_resp_ptr->read_result.content;

			card_mnc_len = data[3];
		}
	}
	else{
		qmi_status = FALSE;
		wpa_printf(MSG_ERROR,
				"MNC read failed=%x\n",qmi_err_code);
	}

	/* Free the allocated read request buffer */
	if (qmi_read_trans_req_ptr) {
		os_free(qmi_read_trans_req_ptr);
		qmi_read_trans_req_ptr = NULL;
	}

	/* Free the allocated read response buffer */
	if (qmi_read_trans_resp_ptr) {
		os_free(qmi_read_trans_resp_ptr);
		qmi_read_trans_resp_ptr = NULL;
	}
	return qmi_status;
} /* wpa_qmi_read_card_imsi */
#endif /* SIM_AKA_IDENTITY_IMSI */

const char * eap_proxy_get_port(void)
{
	int ret = 0;
	const char* eap_proxy_port = NULL;

	char args[EAP_PROXY_PROPERTY_BASEBAND_SIZE] = {0};
	char def[EAP_PROXY_PROPERTY_BASEBAND_SIZE] = {0};

	ret = property_get(EAP_PROXY_PROPERTY_BASEBAND, args, def);
	if (ret > EAP_PROXY_PROPERTY_BASEBAND_SIZE) {
		wpa_printf(MSG_ERROR,"property [%s] has size [%d] that exceeds max [%d]",
				   EAP_PROXY_PROPERTY_BASEBAND,
				   ret,
				   EAP_PROXY_PROPERTY_BASEBAND_SIZE);
		return NULL;
	}

	if(!os_strncmp(EAP_PROXY_BASEBAND_VALUE_MSM, args, 3)) {
	   wpa_printf(MSG_ERROR,"baseband property is set to [%s]", args);
	   eap_proxy_port = QMI_PORT_RMNET_0;
	}
	else if(!os_strncmp(EAP_PROXY_BASEBAND_VALUE_APQ, args, 3)) {
		wpa_printf(MSG_ERROR,"baseband property is set to [%s]", args);
		eap_proxy_port = QMI_PORT_RMNET_0;
	}
	else if(!os_strncmp(EAP_PROXY_BASEBAND_VALUE_SVLTE1, args, 6)) {
		wpa_printf(MSG_ERROR,"baseband property is set to [%s]", args);
		eap_proxy_port = QMI_PORT_RMNET_0;
	}
	else if(!os_strncmp(EAP_PROXY_BASEBAND_VALUE_SVLTE2A, args, 7)) {
		wpa_printf(MSG_ERROR,"baseband property is set to [%s]", args);
		eap_proxy_port = QMI_PORT_RMNET_0;
	}
	else if(!os_strncmp(EAP_PROXY_BASEBAND_VALUE_CSFB, args, 4)) {
		eap_proxy_port = QMI_PORT_RMNET_SDIO_0;
	}
	else if(!os_strncmp(EAP_PROXY_BASEBAND_VALUE_MDMUSB, args, 6)) {
		wpa_printf(MSG_ERROR,"baseband property is set to [%s]", args);
		eap_proxy_port = QMI_PORT_RMNET_USB_0;
	}
	else if(!os_strncmp(EAP_PROXY_BASEBAND_VALUE_SGLTE, args, 5)) {
		wpa_printf(MSG_ERROR,"baseband property is set to [%s]", args);
		eap_proxy_port = QMI_PORT_RMNET_0;
	}
	else if(!os_strncmp(EAP_PROXY_TARGET_FUSION4_5_PCIE, args, 14)) {
		wpa_printf(MSG_ERROR,"baseband property is set to [%s]", args);
		eap_proxy_port = QMI_PORT_RMNET_MHI_0;
	}
#ifdef CONFIG_EAP_PROXY_MSM8994_TARGET
	if ((!os_strncmp(EAP_PROXY_BASEBAND_VALUE_MSM, args, 3)) ||
	    (!os_strncmp(EAP_PROXY_BASEBAND_VALUE_APQ, args, 3)) ||
	    (!os_strncmp(EAP_PROXY_BASEBAND_VALUE_SGLTE, args, 5))) {
		ret = property_get(EAP_PROXY_TARGET_PLATFORM, args, def);
		if (!os_strncmp(EAP_PROXY_TARGET_PLATFORM_MSM8994, args, 7)) {
			wpa_printf(MSG_ERROR,"baseband property is set to [%s]: for 8994 HW", args);
			eap_proxy_port = QMI_PORT_RMNET_0;
		}
	}
#endif /* CONFIG_EAP_PROXY_MSM8994_TARGET */
	return eap_proxy_port;
}

#ifdef CONFIG_EAP_PROXY_MDM_DETECT
static int eap_modem_compatible(struct dev_info *mdm_detect_info)
{
	char args[EAP_PROXY_PROPERTY_BASEBAND_SIZE] = {0};
	int ret = 0;

	/* Get the hardware property */
	ret = property_get(EAP_PROXY_PROPERTY_BASEBAND, args, "");
	if (ret > EAP_PROXY_PROPERTY_BASEBAND_SIZE){
		wpa_printf(MSG_ERROR,"property [%s] has size [%d] that exceeds max [%d]",
			   EAP_PROXY_PROPERTY_BASEBAND,
			   ret,
			   EAP_PROXY_PROPERTY_BASEBAND_SIZE);
		return FALSE;
	}

	/* This will check for the type of hardware, and if the hardware type
	 * needs external modem, it will check if the modem type is external */
	if(!os_strncmp(EAP_PROXY_BASEBAND_VALUE_APQ, args, 3)) {
		for (ret = 0; ret < mdm_detect_info->num_modems; ret++) {
			if (mdm_detect_info->mdm_list[ret].type == MDM_TYPE_EXTERNAL) {
				wpa_printf(MSG_INFO, "eap_proxy: hardware supports external modem");
				return TRUE;
			}
		}
		wpa_printf(MSG_ERROR, "eap_proxy: hardware does not support external modem");
		return FALSE;
	}
	return TRUE;
}
#endif /* CONFIG_EAP_PROXY_MDM_DETECT */

struct eap_proxy_sm *
eap_proxy_init(void *eapol_ctx, struct eapol_callbacks *eapol_cb,
	       void *msg_ctx)
{
	int qmiErrorCode;
	int qmiRetCode;
	struct eap_proxy_sm *eap_proxy;
	qmi_idl_service_object_type    qmi_client_service_obj[MAX_NO_OF_SIM_SUPPORTED];
	const char *eap_qmi_port[MAX_NO_OF_SIM_SUPPORTED];
	int index;
	static Boolean flag = FALSE;
#ifdef CONFIG_EAP_PROXY_MDM_DETECT
	struct dev_info mdm_detect_info;
	int ret = 0;

	/* Call ESOC API to get the number of modems.
	 * If the number of modems is not zero, only then proceed
	 * with the eap_proxy intialization.
	 */
	ret = get_system_info(&mdm_detect_info);
	if (ret > 0)
		wpa_printf(MSG_ERROR, "eap_proxy: Failed to get system info, ret %d", ret);

	if (mdm_detect_info.num_modems == 0) {
		wpa_printf(MSG_ERROR, "eap_proxy: No Modem support for this target"
			   " number of modems is %d", mdm_detect_info.num_modems);
		return NULL;
	}
	wpa_printf(MSG_DEBUG, "eap_proxy: num_modems = %d", mdm_detect_info.num_modems);

	if(eap_modem_compatible(&mdm_detect_info) == FALSE) {
		wpa_printf(MSG_ERROR, "eap_proxy: build does not support EAP-SIM feature");
		return NULL;
	}
#endif /* CONFIG_EAP_PROXY_MDM_DETECT */

	eap_proxy =  os_malloc(sizeof(struct eap_proxy_sm));
	if (NULL == eap_proxy) {
		wpa_printf(MSG_ERROR, "Error memory alloc  for eap_proxy"
						"eap_proxy_init\n");
		return NULL;
	}
	os_memset(eap_proxy, 0, sizeof(*eap_proxy));

	eap_proxy->ctx = eapol_ctx;
	eap_proxy->eapol_cb = eapol_cb;
	eap_proxy->msg_ctx = msg_ctx;
	eap_proxy->proxy_state = EAP_PROXY_INITIALIZE;
	eap_proxy->qmi_state = QMI_STATE_IDLE;
	eap_proxy->key = NULL;
	eap_proxy->iskey_valid = FALSE;
	eap_proxy->is_state_changed = FALSE;
	eap_proxy->isEap = FALSE;
	eap_proxy->eap_type = EAP_TYPE_NONE;
        eap_proxy->user_selected_sim = 0;

#ifdef CONFIG_EAP_PROXY_DUAL_SIM
	wpa_printf (MSG_ERROR, "eap_proxy Initializing for DUAL SIM build %d ", MAX_NO_OF_SIM_SUPPORTED);
#else
	wpa_printf (MSG_ERROR, "eap_proxy Initializing for Single SIM build %d ", MAX_NO_OF_SIM_SUPPORTED);
#endif

	/* initialize QMI */
	eap_proxy_qmi_init_handle = qmi_init(handle_qmi_sys_events, NULL);
	if (eap_proxy_qmi_init_handle < 0) {
		wpa_printf(MSG_ERROR, "Error in qmi_init\n");
		os_free(eap_proxy);
		eap_proxy = NULL;
		return NULL;
	}

	for (index = 0; index < MAX_NO_OF_SIM_SUPPORTED; ++index) {
		/*Get the available port using property get*/
		eap_qmi_port[index] = eap_proxy_get_port();
		eap_proxy->qmihandle[index] = QMI_NO_ERR;

		do {
			if(eap_proxy->qmihandle[index] == QMI_PORT_NOT_OPEN_ERR &&
			   os_strcmp(eap_qmi_port[index], QMI_PORT_RMNET_0) == 0)
				eap_qmi_port[index] = QMI_PORT_RMNET_1;
			/* initialize the QMI connection */
			qmiRetCode = qmi_dev_connection_init(eap_qmi_port[index], &qmiErrorCode);
			if (QMI_NO_ERR != qmiRetCode) {
				wpa_printf(MSG_ERROR, "Error in qmi_connection_init\n");
				flag = FALSE;
				break;
			}

			/* initialize the QMI EAP Service for client n or SIM n*/
			wpa_printf(MSG_INFO,
			"eap_proxy: Initializing the QMI EAP Services for client %d\n", index+1);
			eap_proxy->qmihandle[index] = qmi_eap_srvc_init_client(eap_qmi_port[index],
								&handle_qmi_eap_ind,
								eap_proxy, &qmiErrorCode);
		} while(eap_proxy->qmihandle[index] == QMI_PORT_NOT_OPEN_ERR &&
			os_strcmp(eap_qmi_port[index], QMI_PORT_RMNET_0) == 0);

		if(QMI_NO_ERR != qmiRetCode)
			continue;
		if (0 >= eap_proxy->qmihandle[index]) {
			wpa_printf(MSG_ERROR, "Unable to initialize service client %d;"
						" error_ret=%d; error_code=%d\n",
						index+1, eap_proxy->qmihandle[index], qmiErrorCode);
			flag = FALSE;
			continue;
		}
		wpa_printf(MSG_ERROR, "eap_proxy: eap_proxy_init: qmihandle[%d] = %d\n",
				index, eap_proxy->qmihandle[index]);

#ifdef SIM_AKA_IDENTITY_IMSI
		if (FALSE == qmi_uim_svc_client_initialized[index]) {
			/* Init QMI_UIM service for EAP-SIM/AKA */
			qmi_client_service_obj[index] = uim_get_service_object_v01();

			qmiErrorCode = qmi_client_init(eap_qmi_port[index],
							qmi_client_service_obj[index],
							wpa_qmi_client_indication_cb,
							qmi_client_service_obj[index],
							&wpa_uim[index].qmi_uim_svc_client_ptr);

			if ((wpa_uim[index].qmi_uim_svc_client_ptr == NULL) || (qmiErrorCode > 0)) {
				wpa_printf(MSG_ERROR, "Could not register with QMI UIM Service,"
					"qmi_uim_svc_client_ptr: %p,qmi_err_code: %d\n",
					wpa_uim[index].qmi_uim_svc_client_ptr, qmiErrorCode);
					wpa_uim[index].qmi_uim_svc_client_ptr = NULL;
					flag = FALSE;
					continue;
			}
			qmi_uim_svc_client_initialized[index] = TRUE;

			/* Register the card events with the QMI / UIM */
			wpa_qmi_register_events(index);
			flag = TRUE;
		} else {
			wpa_printf (MSG_ERROR, "QMI EAP service client is already initialized\n");
		}
#endif /* SIM_AKA_IDENTITY_IMSI */
	}

	if ( flag == FALSE ) {
		wpa_printf(MSG_ERROR, "eap_proxy: flag = %d proxy init failed\n", flag);
		os_free(eap_proxy);
		eap_proxy = NULL;
		return NULL;
	}

	eap_proxy->proxy_state = EAP_PROXY_IDLE;
	eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapSuccess, FALSE);
	eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapFail, FALSE);
	eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapRestart, FALSE);
	eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapResp, FALSE);
	eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapNoResp, FALSE);
	wpa_printf (MSG_ERROR, "Eap_proxy initialized successfully\n");

	return eap_proxy;
}


void eap_proxy_deinit(struct eap_proxy_sm *eap_proxy)
{
	int qmiRetCode;
	int qmiErrorCode;
	int index;

	if (NULL == eap_proxy)
		return;

	eap_proxy->proxy_state = EAP_PROXY_DISABLED;

	for (index = 0; index < MAX_NO_OF_SIM_SUPPORTED; ++index) {
		if (TRUE == eap_auth_session_flag[index]) {
			wpa_printf (MSG_ERROR, "eap_proxy: in eap_proxy_deinit qmihandle[%d] = %d\n",
					index, eap_proxy->qmihandle[index]);
			/* end the current EAP session */
			qmiRetCode = qmi_eap_auth_end_eap_session(
						eap_proxy->qmihandle[index],
						&qmiErrorCode);
			if (QMI_NO_ERR != qmiRetCode) {
				wpa_printf(MSG_ERROR, "eap_proxy: Unable to end the EAP session for "
						"client %d; error_ret=%d; error_code=%d\n",
						index+1, qmiRetCode,
						qmiErrorCode);
			} else {
				wpa_printf(MSG_ERROR, "eap_proxy: Ended the QMI EAP session for "
						"client %d\n",
						index+1);
				eap_auth_session_flag[index] = FALSE;
			}
		} else {
			wpa_printf (MSG_ERROR, "eap_proxy: session not started for client = %d\n", index+1);
			continue;
		}

		if (TRUE == qmi_uim_svc_client_initialized[index]) {
			qmiRetCode = qmi_client_release(wpa_uim[index].qmi_uim_svc_client_ptr);
			if (QMI_NO_ERR != qmiRetCode) {
				wpa_printf (MSG_ERROR, "Unable to Releas the connection"
					    " to a service for client=%d; error_ret=%d\n;",
					    index+1, qmiRetCode);
			}

			qmiRetCode = qmi_eap_srvc_release_client(eap_proxy->qmihandle[index],
								 &qmiErrorCode);
			if (QMI_NO_ERR != qmiRetCode) {
				wpa_printf (MSG_ERROR, "Unable to release the QMI EAP"
					    "service client = %d; error_ret=%d;"
					    "error_code=%d\n\n", index+1, qmiRetCode,
					    qmiErrorCode);
			} else {
				wpa_printf(MSG_ERROR, "Released QMI EAP service client\n");
				qmi_uim_svc_client_initialized[index] = FALSE;
			}
		} else {
			wpa_printf (MSG_ERROR, "eap_proxy: Service client %d is not initilaized\n", index+1);
			continue;
		}
	}

	if (NULL != eap_proxy->key) {
		os_free(eap_proxy->key);
		eap_proxy->key = NULL;
	}

	/* Release QMI */
	qmi_release(eap_proxy_qmi_init_handle);

	eap_proxy->iskey_valid = FALSE;
	eap_proxy->is_state_changed = FALSE;
        eap_proxy->user_selected_sim = 0;

	os_free(eap_proxy);
	eap_proxy = NULL;
	wpa_printf(MSG_INFO, "eap_proxy Deinitialzed\n");
}

/* Call-back function to process an authentication result indication
*  from QMI EAP service */
static void handle_qmi_eap_ind
(
	int userHandle, qmi_service_id_type serviceId,
	void *userData, qmi_eap_indication_id_type indId,
	qmi_eap_indication_data_type *indData
)
{
	struct eap_proxy_sm *sm = (struct eap_proxy_sm *)userData;
	wpa_printf(MSG_ERROR, "Handle_qmi_eap_ind serviceId =%d indId = %d \n", serviceId , indId);

	if (NULL == sm || (QMI_EAP_SERVICE != serviceId)) {
		wpa_printf(MSG_ERROR, "Bad param: serviceId=%d\n", serviceId);
		return;
	}

	wpa_printf(MSG_ERROR, "eap_proxy: user_selected_sim = %d\n", sm->user_selected_sim+1);
	wpa_printf(MSG_ERROR, "eap_proxy: qmihandle = %d\n", sm->qmihandle[sm->user_selected_sim]);
	wpa_printf(MSG_ERROR, "eap_proxy: from call userHandle = %d\n", userHandle);
	if (sm->qmihandle[sm->user_selected_sim] != userHandle) {
		wpa_printf(MSG_ERROR, "User handle is invalid: cached=%d;"
				" given=%d\n",
				sm->qmihandle[sm->user_selected_sim], userHandle);
		return;
	}

	switch (indId) {
	case QMI_EAP_SRVC_INVALID_IND_MSG:
		sm->srvc_result = EAP_PROXY_QMI_SRVC_FAILURE;
		break;

	case QMI_EAP_SRVC_SESSION_RESULT_IND_MSG:
		if (NULL != indData) {
                        if ((indData->auth_result == QMI_EAP_AUTHENTICATION_SUCCESS) &&
                                (QMI_STATE_RESP_TIME_OUT != sm->qmi_state)) {
				sm->proxy_state = EAP_PROXY_AUTH_SUCCESS;
                                sm->qmi_state = QMI_STATE_RESP_RECEIVED;
	wpa_printf(MSG_ERROR, "Handle_qmi_eap_ind EAP PROXY AUTH SUCCESS \n");
			} else {
				sm->proxy_state = EAP_PROXY_AUTH_FAILURE;
	wpa_printf(MSG_ERROR, "Handle_qmi_eap_ind EAP PROXY AUTH FAILURE \n");
			}
			sm->srvc_result = EAP_PROXY_QMI_SRVC_SUCCESS;
		} else {
			wpa_printf(MSG_ERROR, "Receving a NULL auth result\n");
			sm->srvc_result = EAP_PROXY_QMI_SRVC_FAILURE;
			sm->proxy_state = EAP_PROXY_AUTH_FAILURE;
		}
		break;

	default:
		wpa_printf(MSG_ERROR, "An unexpected indication Id=%d"
							" is given\n", indId);
	break;
	}
	return;
}


/* Call-back function to process an EAP response from QMI EAP service */
static void handle_qmi_eap_reply(
	int userHandle, qmi_service_id_type serviceId, int sysErrCode,
	int qmiErrCode, void *userData, qmi_eap_async_rsp_id_type rspId,
	qmi_eap_async_rsp_data_type *rspData
)
{
	struct eap_proxy_sm *eap_proxy = (struct eap_proxy_sm *)userData;
	u8 *resp_data;
	u32 length;

	if (QMI_STATE_RESP_PENDING == eap_proxy->qmi_state) {
		if (NULL == eap_proxy || QMI_EAP_SERVICE != serviceId ||
				QMI_EAP_SEND_EAP_PKT_RSP_ID != rspId) {
			wpa_printf(MSG_ERROR, "Bad Param: serviceId=%d;"
				 " rspId=%d\n", serviceId, rspId);
			eap_proxy->qmi_state = QMI_STATE_RESP_TIME_OUT;
			return;
		}

	wpa_printf(MSG_ERROR, "eap_proxy: user_selected_sim = %d\n", eap_proxy->user_selected_sim+1);
	wpa_printf(MSG_ERROR, "eap_proxy: qmihandle = %d\n",
				eap_proxy->qmihandle[eap_proxy->user_selected_sim]);
	wpa_printf(MSG_ERROR, "eap_proxy: from call userHandle = %d\n", userHandle);
		if (eap_proxy->qmihandle[eap_proxy->user_selected_sim] != userHandle) {
			wpa_printf(MSG_ERROR, "User handle is invalid:"
					" cached=%d; given=%d\n",
					eap_proxy->qmihandle[eap_proxy->user_selected_sim],
					userHandle);
			eap_proxy->qmi_state = QMI_STATE_RESP_TIME_OUT;
			return;
		}

		if (QMI_NO_ERR != sysErrCode) {
			wpa_printf(MSG_ERROR, "An error is encountered with"
				" the request: sysErrorCode=%d; qmiErrCode=%d\n",
							sysErrCode, qmiErrCode);
			eap_proxy->qmi_state = QMI_STATE_RESP_TIME_OUT;
			return;
		}

		if (NULL == rspData) {
			wpa_printf(MSG_ERROR, "Response data is NULL\n");
			eap_proxy->qmi_state = QMI_STATE_RESP_TIME_OUT;
			return;
		}

		/* ensure the reply packet exists  */
		if (!rspData->eap_send_pkt_resp.resp_data) {
			wpa_printf(MSG_ERROR, "Reply packet is NULL\n");
			eap_proxy->qmi_state = QMI_STATE_RESP_TIME_OUT;
			return;
		}

		length = rspData->eap_send_pkt_resp.length;
		eap_proxy->qmi_resp_data.eap_send_pkt_resp.length = length;
/* allocate a buffer to store the response data; size is EAP resp len field */
		eap_proxy->qmi_resp_data.eap_send_pkt_resp.resp_data =
				os_malloc(rspData->eap_send_pkt_resp.length);

		resp_data =
		(u8 *)eap_proxy->qmi_resp_data.eap_send_pkt_resp.resp_data;

		if (NULL == resp_data) {
			wpa_printf(MSG_ERROR, "Unable to allocate memory for"
							 " reply packet\n");
			eap_proxy->qmi_state = QMI_STATE_RESP_TIME_OUT;

			return;
		}

		/* copy the response data to the allocated buffer */
		os_memcpy(resp_data,
			rspData->eap_send_pkt_resp.resp_data, length);
		eap_proxy->qmi_state = QMI_STATE_RESP_RECEIVED;
		wpa_printf(MSG_ERROR, "*****************HANDLE_QMI_EAP_REPLY CALLBACK ENDDED ********************* ");

		wpa_printf(MSG_ERROR, "Dump Resp Data len %d\n", length);
		dump_buff(resp_data, length);

	}
	return;
}

static enum eap_proxy_status eap_proxy_process(struct eap_proxy_sm  *eap_proxy,
					u8 *eapReqData, int eapReqDataLen, struct eap_sm *eap_sm)
{
	struct eap_hdr *hdr;
	int qmiErrorCode;
	enum eap_proxy_status proxy_status = EAP_PROXY_SUCCESS;

	hdr = (struct eap_hdr *)eapReqData;
	if ((EAP_CODE_REQUEST == hdr->code) &&
		(EAP_TYPE_IDENTITY == eapReqData[4])) {
		if (eap_proxy_eapol_sm_get_bool(eap_proxy, EAPOL_eapRestart) &&
		    eap_proxy_eapol_sm_get_bool(eap_proxy, EAPOL_portEnabled)) {
			wpa_printf (MSG_ERROR, "eap_proxy: Already Authenticated. "
				     "Clear all the flags");
			eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapSuccess, FALSE);
			eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapFail, FALSE);
			eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapResp, FALSE);
			eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapNoResp, FALSE);
			if (eap_proxy->key) {
                                os_free(eap_proxy->key);
                                eap_proxy->key = NULL;
                        }
                        eap_proxy->iskey_valid = FALSE;
                        eap_proxy->is_state_changed = TRUE;
		}
		eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapRestart, FALSE);

		if(eap_proxy_build_identity(eap_proxy, hdr->identifier, eap_sm)) {
			eap_proxy->proxy_state = EAP_PROXY_IDENTITY;
		}
		else {
			wpa_printf(MSG_ERROR, "Error in build identity\n");
			return EAP_PROXY_FAILURE;
		}
	}
	wpa_printf(MSG_ERROR, "Dump ReqData len %d\n", eapReqDataLen);
	dump_buff(eapReqData, eapReqDataLen);

	wpa_printf(MSG_ERROR, "eap_proxy: SIM selected by User: Selected sim = %d\n", eap_proxy->user_selected_sim+1);
	if (eap_proxy->qmi_state != QMI_STATE_IDLE) {
		wpa_printf(MSG_ERROR, "Error in QMI state=%d\n",
					 eap_proxy->qmi_state);
		return EAP_PROXY_FAILURE;
	}

	eap_proxy->qmi_state = QMI_STATE_RESP_PENDING;

	eap_proxy->qmiTransactionId = qmi_eap_auth_send_eap_packet(
			eap_proxy->qmihandle[eap_proxy->user_selected_sim],
			&handle_qmi_eap_reply, eap_proxy,
			eapReqData, eapReqDataLen, &qmiErrorCode);

	if (0 <= eap_proxy->qmiTransactionId) {
		wpa_printf (MSG_ERROR, "eap_proxy: In eap_proxy_process case %d\n", hdr->code);
		switch (hdr->code) {
		case EAP_CODE_SUCCESS:
			if (EAP_PROXY_SUCCESS !=
				eap_proxy_qmi_response_wait(eap_proxy)) {
				eap_proxy->proxy_state = EAP_PROXY_DISCARD;
				eap_proxy_eapol_sm_set_bool(eap_proxy,
							EAPOL_eapNoResp, TRUE);
				return EAP_PROXY_FAILURE;
			} else if( eap_proxy->proxy_state == EAP_PROXY_AUTH_SUCCESS ) {
				eap_proxy_getKey(eap_proxy);
				eap_proxy_eapol_sm_set_bool(eap_proxy,
						 EAPOL_eapSuccess, TRUE);
	/*
	 * RFC 4137 does not clear eapReq here, but this seems to be required
	 * to avoid processing the same request twice when state machine is
	 * initialized.
	 */
			eap_proxy_eapol_sm_set_bool(eap_proxy,
							EAPOL_eapReq, FALSE);

	/*
	 * RFC 4137 does not set eapNoResp here, but this seems to be required
	 * to get EAPOL Supplicant backend state machine into SUCCESS state. In
	 * addition, either eapResp or eapNoResp is required to be set after
	 * processing the received EAP frame.
	 */
			eap_proxy_eapol_sm_set_bool(eap_proxy,
						EAPOL_eapNoResp, TRUE);

			wpa_msg(eap_proxy->msg_ctx, MSG_INFO, WPA_EVENT_EAP_SUCCESS
				"EAP authentication completed successfully");

			eap_proxy->is_state_changed = TRUE;

				/* Retrieve the keys  and store*/
			} else if( eap_proxy->proxy_state == EAP_PROXY_AUTH_FAILURE ){

				eap_proxy_eapol_sm_set_bool(eap_proxy,
						EAPOL_eapFail, TRUE);
				eap_proxy_eapol_sm_set_bool(eap_proxy,
						EAPOL_eapReq, FALSE);
				eap_proxy_eapol_sm_set_bool(eap_proxy,
						EAPOL_eapNoResp, TRUE);
				eap_proxy->is_state_changed = TRUE;

			}

			break;

		case EAP_CODE_FAILURE:
			wpa_printf (MSG_ERROR, "in eap_proxy_process case EAP_CODE_FAILURE\n");
			eap_proxy->proxy_state = EAP_PROXY_AUTH_FAILURE;
			eap_proxy_eapol_sm_set_bool(eap_proxy,
						EAPOL_eapFail, TRUE);

	/*
	 * RFC 4137 does not clear eapReq here, but this seems to be required
	 * to avoid processing the same request twice when state machine is
	 * initialized.
	*/
			eap_proxy_eapol_sm_set_bool(eap_proxy,
						EAPOL_eapReq, FALSE);

	/*
	 * RFC 4137 does not set eapNoResp here. However, either eapResp or
	 * eapNoResp is required to be set after processing the received EAP
	 * frame.
	 */
			eap_proxy_eapol_sm_set_bool(eap_proxy,
						EAPOL_eapNoResp, TRUE);

			wpa_msg(eap_proxy->msg_ctx, MSG_INFO, WPA_EVENT_EAP_FAILURE
				"EAP authentication failed");

			eap_proxy->is_state_changed = TRUE;
			break;

		case EAP_CODE_REQUEST:
					eap_proxy->proxy_state = EAP_PROXY_SEND_RESPONSE;
			if (EAP_PROXY_SUCCESS !=
				eap_proxy_qmi_response_wait(eap_proxy)) {
				eap_proxy->proxy_state = EAP_PROXY_DISCARD;
				eap_proxy_eapol_sm_set_bool(eap_proxy,
							EAPOL_eapNoResp, TRUE);
				return EAP_PROXY_FAILURE;
			} else {
				eap_proxy_eapol_sm_set_bool(eap_proxy,
							EAPOL_eapResp, TRUE);
				eap_proxy->proxy_state =
						EAP_PROXY_SEND_RESPONSE;
			}

			eap_proxy_eapol_sm_set_bool(eap_proxy,
						EAPOL_eapReq, FALSE);
			eap_proxy->is_state_changed = TRUE;
			break;

		default:
			wpa_printf(MSG_ERROR, "Error in sending EAP packet;"
					 " error_code=%d\n", qmiErrorCode);
			eap_proxy->proxy_state = EAP_PROXY_DISCARD;
			eap_proxy_eapol_sm_set_bool(eap_proxy,
				EAPOL_eapNoResp, TRUE);
			return EAP_PROXY_FAILURE;
		}
	} else {
		wpa_printf(MSG_ERROR, "Error in sending EAP packet;"
					 " error_code=%d\n", qmiErrorCode);
		eap_proxy->proxy_state = EAP_PROXY_DISCARD;
		eap_proxy_eapol_sm_set_bool(eap_proxy, EAPOL_eapNoResp, TRUE);
		return EAP_PROXY_FAILURE;
	}

	return EAP_PROXY_SUCCESS;
}



static u8 *eap_proxy_getKey(struct eap_proxy_sm *eap_proxy)
{
	int qmiErrorCode;
	int qmiRetCode;

	if (NULL == eap_proxy->key)
		eap_proxy->key = os_malloc(EAP_PROXY_KEYING_DATA_LEN);

	if (NULL == eap_proxy->key)
		return NULL;

	qmiRetCode = qmi_eap_auth_get_session_keys(eap_proxy->qmihandle[eap_proxy->user_selected_sim],
		eap_proxy->key, EAP_PROXY_KEYING_DATA_LEN, &qmiErrorCode);

	/* see if the MSK is acquired successfully */
	if (QMI_NO_ERR != qmiRetCode) {
		wpa_printf(MSG_ERROR, "Unable to get session keys;"
				 " qmiErrorCode=%d", qmiErrorCode);
		os_free(eap_proxy->key);
		eap_proxy->key = NULL;
		return NULL;
	}
	eap_proxy->iskey_valid = TRUE;
	eap_proxy->proxy_state = EAP_PROXY_AUTH_SUCCESS;

	wpa_printf(MSG_ERROR, "eap_proxy_getkey EAP KEYS ");
	dump_buff(eap_proxy->key, EAP_PROXY_KEYING_DATA_LEN);
	return eap_proxy->key;
}


/**
 * eap_key_available - Get key availability (eapKeyAvailable variable)
 * @sm: Pointer to EAP state machine allocated with eap_sm_init()
 * Returns: 1 if EAP keying material is available, 0 if not
 */
int eap_proxy_key_available(struct eap_proxy_sm *sm)
{
	return sm ? sm->iskey_valid : 0;
}


static int eap_proxy_is_state_changed(struct eap_proxy_sm *sm)
{
	if (NULL == sm)
		return 0;

	if (TRUE == sm->is_state_changed) {
		sm->is_state_changed = FALSE;
		return 1;
	} else {
		return 0;
	}
}


/**
 * eap_get_eapKeyData - Get master session key (MSK) from EAP state machine
 * @sm: Pointer to EAP state machine allocated with eap_sm_init()
 * @len: Pointer to variable that will be set to number of bytes in the key
 * Returns: Pointer to the EAP keying data or %NULL on failure
 *
 * Fetch EAP keying material (MSK, eapKeyData) from the EAP state machine. The
 * key is available only after a successful authentication. EAP state machine
 * continues to manage the key data and the caller must not change or free the
 * returned data.
 */
const u8 * eap_proxy_get_eapKeyData(struct eap_proxy_sm *sm, size_t *len)
{
	if (sm == NULL || sm->key == NULL) {
		*len = 0;
		return NULL;
	}

	*len = EAP_PROXY_KEYING_DATA_LEN;
	return sm->key;
}

/**
 * eap_proxy_get_eapRespData - Get EAP response data
 * @sm: Pointer to EAP state machine allocated with eap_sm_init()
 * @len: Pointer to variable that will be set to the length of the response
 * Returns: Pointer to the EAP response (eapRespData) or %NULL on failure
 *
 * Fetch EAP response (eapRespData) from the EAP state machine. This data is
 * available when EAP state machine has processed an incoming EAP request. The
 * EAP state machine does not maintain a reference to the response after this
 * function is called and the caller is responsible for freeing the data.
 */
struct wpabuf * eap_proxy_get_eapRespData(struct eap_proxy_sm *eap_proxy)
{
	struct wpabuf *resp;
	int len;
//	int i;

	wpa_printf(MSG_ERROR, "eap_proxy: eap_proxy_get_eapRespData");
        if ( (eap_proxy == NULL) ||
             (eap_proxy->qmi_resp_data.eap_send_pkt_resp.resp_data == NULL)
           )
        {
                return NULL;
        }

        len = eap_proxy->qmi_resp_data.eap_send_pkt_resp.length;
	wpa_printf(MSG_ERROR, "eap_proxy: eap_proxy_get_eapRespData len = %d", len);
	resp = wpabuf_alloc(len);
	if (resp == NULL) {
		wpa_printf(MSG_ERROR, "eap_proxy: buf allocation failed\n");
		return NULL;
	}

	resp->used = len;
	os_memcpy(resp->buf, eap_proxy->qmi_resp_data.eap_send_pkt_resp.resp_data,
		   len);
/*
	for (i = 0; i < len; i++) {
		wpa_printf (MSG_ERROR, "%c", resp->buf[i]);
	}
*/
        eap_proxy->qmi_resp_data.eap_send_pkt_resp.resp_data = NULL;
        eap_proxy->qmi_resp_data.eap_send_pkt_resp.length = 0;

        return resp;
}


static enum eap_proxy_status eap_proxy_qmi_response_wait(struct eap_proxy_sm *eap_proxy)
{

	int count = 0;

	wpa_printf(MSG_DEBUG, "eap_proxy_qmi_response_wait: Start blocking "
		   "wait");
	do {
		count++;
		if (count > QMI_RESP_TIME_OUT / 2) {
			wpa_printf(MSG_ERROR,
				   "eap_proxy_qmi_response_wait "
				   "!QMI STATE %d TIME_OUT\n",
				   eap_proxy->qmi_state);
			eap_proxy->qmi_state = QMI_STATE_RESP_TIME_OUT;
			break;
		}

		os_sleep(0, 2000);

		if ((QMI_STATE_RESP_RECEIVED == eap_proxy->qmi_state) ||
		   (QMI_STATE_RESP_TIME_OUT == eap_proxy->qmi_state))
			break;
	} while (1);

	wpa_printf(MSG_DEBUG, "eap_proxy_qmi_response_wait: Wait done after %d "
		   "iterations: qmi_state=%d", count,
		   eap_proxy->qmi_state);

	if (QMI_STATE_RESP_TIME_OUT == eap_proxy->qmi_state) {
		wpa_printf(MSG_ERROR, "QMI state Response Time out\n");
		eap_proxy->proxy_state = EAP_PROXY_DISCARD;
		return EAP_PROXY_FAILURE;
	}
	eap_proxy->qmi_state = QMI_STATE_IDLE;

	return EAP_PROXY_SUCCESS;
}


static void eap_proxy_eapol_sm_set_bool(struct eap_proxy_sm *sm,
			enum eapol_bool_var var, Boolean value)
{
	sm->eapol_cb->set_bool(sm->ctx, var, value);
}


static Boolean eap_proxy_eapol_sm_get_bool(struct eap_proxy_sm *sm,
			 enum eapol_bool_var var)
{
	return  sm->eapol_cb->get_bool(sm->ctx, var);
}


int eap_proxy_sm_step(struct eap_proxy_sm *sm, struct eap_sm *eap_sm)
{
	if ((sm->proxy_state != EAP_PROXY_INITIALIZE) &&
				 (sm->proxy_state != EAP_PROXY_DISABLED)) {
		if (TRUE == sm->isEap) {
			if(!eap_proxy_process(sm, sm->eapReqData,
						 sm->eapReqDataLen,eap_sm)) {
				sm->proxy_state = EAP_PROXY_AUTH_FAILURE;
				eap_proxy_eapol_sm_set_bool(sm, EAPOL_eapRestart, TRUE);
			}
			sm->isEap = FALSE;
		}
	}
	return eap_proxy_is_state_changed(sm);
}


enum eap_proxy_status
eap_proxy_packet_update(struct eap_proxy_sm *eap_proxy, u8 *eapReqData,
			int eapReqDataLen)
{
	eap_proxy->eapReqData = eapReqData;
	eap_proxy->eapReqDataLen = eapReqDataLen;
	eap_proxy->isEap = TRUE;
	return EAP_PROXY_SUCCESS;
}


static void dump_buff(u8 *buff, int len)
{
	int i ;

	wpa_printf(MSG_ERROR, "---- EAP Buffer----LEN %d\n",len);
	for (i = 0; i < len; i++) {
		if (0 == i%8)
			wpa_printf(MSG_DEBUG, " \n");
		wpa_printf(MSG_ERROR, "0x%x  ", buff[i]);
	}
	return;
}
static char bin_to_hexchar(u8 ch)
{
	if (ch < 0x0a) {
		return ch + '0';
	}
	return ch + 'a' - 10;
}

static Boolean eap_proxy_build_identity(struct eap_proxy_sm *eap_proxy, u8 id, struct eap_sm *eap_sm)
{
	struct eap_hdr *resp;
	unsigned int len;
	u8 identity_len = 0, ret;
	u8 imsi_id_len = 0;
	int mnc_len = -1;
	u8 *pos;
	int qmiRetCode;
	int qmiErrorCode;
	u8 idx = 0, mcc_idx = 0;
	unsigned char *identity = NULL;
	unsigned char *imsi_identity = NULL;
	qmi_eap_auth_start_eap_params_type   eap_auth_start;
	struct eap_method_type *m;
	eap_identity_format_e identity_format = EAP_IDENTITY_ANNONYMOUS;
	Boolean simEnabled = FALSE, akaEnabled = FALSE;
	struct eap_peer_config *config = eap_get_config(eap_sm);
	const char *realm_3gpp = "@wlan.mnc000.mcc000.3gppnetwork.org";
	int sim_num;

	wpa_printf(MSG_ERROR, "eap_proxy: %s\n", __func__);
	sim_num = config->sim_num - 1;
	eap_auth_start.params_mask = 0;
	eap_auth_start.user_id = NULL;
	eap_auth_start.user_id_len = 0;
	eap_auth_start.eap_meta_id = 0;
	eap_auth_start.eap_method_mask = QMI_EAP_METHOD_MASK_UNSET;
	m = config->eap_methods;

	if (sim_num >= MAX_NO_OF_SIM_SUPPORTED || sim_num < 0) {
		wpa_printf (MSG_ERROR, "eap_proxy: Invalid SIM selected sim by user = %d\n",
			     sim_num+1);
		return FALSE;
	}
	wpa_printf(MSG_ERROR, "eap_proxy: User selected sim = %d\n", sim_num+1);

	for (idx = 0; m[idx].vendor != EAP_VENDOR_IETF ||
			 m[idx].method != EAP_TYPE_NONE; idx++) {
		if (m[idx].method == EAP_TYPE_AKA) {
			akaEnabled = TRUE;
			eap_auth_start.eap_method_mask |= QMI_EAP_AKA_METHOD_MASK;
			wpa_printf(MSG_ERROR, "AKA Enabled\n");
		} else if (m[idx].method == EAP_TYPE_SIM) {
			simEnabled = TRUE;
			eap_auth_start.eap_method_mask |= QMI_EAP_SIM_METHOD_MASK;
			wpa_printf(MSG_ERROR, "SIM Enabled\n");
#ifdef CONFIG_EAP_PROXY_AKA_PRIME
		} else if (m[idx].method == EAP_TYPE_AKA_PRIME) {
			eap_auth_start.eap_method_mask |= QMI_EAP_AKA_PRIME_METHOD_MASK;
			wpa_printf(MSG_ERROR, "AKA Prime Enabled\n");
#endif /* CONFIG_EAP_PROXY_AKA_PRIME */
		}
	}

	eap_auth_start.params_mask |= QMI_EAP_AUTH_START_EAP_METHOD_MASK_PARAM;

	idx = 0;
#ifdef SIM_AKA_IMSI_RAW_ENABLED

	identity_format = EAP_IDENTITY_IMSI_RAW;
	eap_auth_start.params_mask |= QMI_EAP_AUTH_START_EAP_USER_ID_PARAM;
	wpa_printf(MSG_ERROR, "EAP_IDENTITY_IMSI_RAW selected %d \n", eap_auth_start.user_id_len);

#else /* SIM_AKA_IMSI_RAW_ENABLED */

	if (config->identity_len && config->identity != NULL) {
		for (idx = 0; idx < config->identity_len; idx++) {
			if (config->identity[idx] == 64) {
				wpa_printf(MSG_ERROR, "@ found \n");
				mcc_idx = idx;
				if ((mcc_idx + 18) > config->identity_len)
					mcc_idx = 0;
				else {
					/* Looking for mnc and mcc pattern */
					if (109 == config->identity[mcc_idx + 6] &&
						(110 == config->identity[mcc_idx + 7]) &&
						(99 == config->identity[mcc_idx + 8]) &&
						(109 == config->identity[mcc_idx + 13]) &&
						(99 == config->identity[mcc_idx + 14]) &&
						(99 == config->identity[mcc_idx + 15])) {
						mcc_idx += 9;
					} else
						mcc_idx = 0;
				}
				break;
			}
		}

		wpa_printf(MSG_ERROR, "idx %d\n", idx);
		wpa_printf(MSG_ERROR, "mcc idx %d\n", mcc_idx);

		if (!idx && (config->identity_len == 1)) {
			/* config file : @ */
			config->identity_len = 0;
			identity_format = EAP_IDENTITY_IMSI_3GPP_REALM;
			wpa_printf(MSG_ERROR, "EAP_IDENTITY_IMSI_3GPP_REALM selected \n");
		} else if (idx && (idx < config->identity_len) && (config->identity != NULL)) {

			/* config file : <>@<> or <>@<wlan.mnc000.mcc000.<>.<> */
			identity_len = config->identity_len;
			identity = os_malloc(config->identity_len);

			if (NULL != identity) {
				os_memset(identity, 0, config->identity_len);
				os_memcpy(identity, config->identity,
						config->identity_len);
			}

			/* To Do for 3GPP realm */
			identity_format = EAP_IDENTITY_CFG_3GPP_REALM;
			eap_auth_start.params_mask |= QMI_EAP_AUTH_START_EAP_USER_ID_PARAM;
			wpa_printf(MSG_ERROR, "EAP_IDENTITY_CFG_3GPP_REALM selected %d \n", eap_auth_start.user_id_len);

		} else if ((idx == config->identity_len) && config->identity_len &&
					(config->identity != NULL)) {

			/* config file : <identity in RAW format >*/
			identity_len = config->identity_len;
			identity = os_malloc(config->identity_len);

			if (NULL != identity) {
				os_memset(identity, 0, config->identity_len);
				os_memcpy(identity, config->identity,
						config->identity_len);
			}

			identity_format = EAP_IDENTITY_CFG_RAW;
			eap_auth_start.params_mask |= QMI_EAP_AUTH_START_EAP_USER_ID_PARAM;
			wpa_printf(MSG_ERROR, "EAP_IDENTITY_CFG_RAW selected %d \n", eap_auth_start.user_id_len);
		} else if (!idx && mcc_idx) {

			/* config file: @wlan.mnc000.mcc000.<>.<> */
			identity_len = config->identity_len;
			identity = os_malloc(config->identity_len);

			if (NULL != identity) {
				os_memset(identity, 0, config->identity_len);
				os_memcpy(identity, config->identity,
					 config->identity_len);
			}

			identity_format = EAP_IDENTITY_IMSI_3GPP_REALM;
			eap_auth_start.params_mask |= QMI_EAP_AUTH_START_EAP_USER_ID_PARAM;
			wpa_printf(MSG_ERROR, "config EAP_IDENTITY_IMSI_3GPP_REALM selected %d \n", eap_auth_start.user_id_len);
		}
	} else {

		if (config->anonymous_identity_len && config->anonymous_identity != NULL) {

			eap_auth_start.eap_meta_id_len = config->anonymous_identity_len;
			eap_auth_start.eap_meta_id = os_malloc(config->anonymous_identity_len);

			if (eap_auth_start.eap_meta_id != NULL) {
				os_memcpy(eap_auth_start.eap_meta_id ,
						config->anonymous_identity ,
						config->anonymous_identity_len);
			}

			identity_format = EAP_IDENTITY_ANNONYMOUS;
			eap_auth_start.params_mask |= QMI_EAP_AUTH_START_EAP_META_ID_PARAM;
			wpa_printf(MSG_ERROR, "EAP_IDENTITY_ANNONYMOUS selected user id %d, annonymous %d\n",
						eap_auth_start.user_id_len, eap_auth_start.eap_meta_id_len);
		} else {
			/* config file doesn't contain any identity
				generating IMSI@realm */
			identity_format = EAP_IDENTITY_IMSI_3GPP_REALM;
			eap_auth_start.params_mask |= QMI_EAP_AUTH_START_EAP_USER_ID_PARAM;
			wpa_printf(MSG_ERROR, "EAP_IDENTITY_IMSI_3GPP_REALM id len %d \n", eap_auth_start.user_id_len);
		}
	}
#endif /* SIM_AKA_IMSI_RAW_ENABLED */
	if (identity_format == EAP_IDENTITY_IMSI_3GPP_REALM ||
		identity_format == EAP_IDENTITY_IMSI_RAW || mcc_idx) {

		wpa_printf(MSG_ERROR, "eap_proxy: EAP_IDENTITY_IMSI_3GPP_REALM is selected\n");
		if (!wpa_qmi_read_card_status(sim_num)) {
			wpa_printf(MSG_INFO, "Read Card Status failed, return\n");
			if (eap_auth_start.eap_meta_id != NULL) {
				os_free(eap_auth_start.eap_meta_id);
				eap_auth_start.eap_meta_id = NULL;
			}
			if (eap_auth_start.user_id != NULL) {
				os_free(eap_auth_start.user_id);
				eap_auth_start.user_id = NULL;
			}
			if (NULL != identity) {
				os_free(identity);
				identity = NULL;
			}
			return FALSE;
		}

		if (!wpa_qmi_read_card_imsi(sim_num)) {
			wpa_printf(MSG_INFO, "Read Card IMSI failed, return\n");
			if (eap_auth_start.eap_meta_id != NULL) {
				os_free(eap_auth_start.eap_meta_id);
				eap_auth_start.eap_meta_id = NULL;
			}
			if (eap_auth_start.user_id != NULL) {
				os_free(eap_auth_start.user_id);
				eap_auth_start.user_id = NULL;
			}
			if (NULL != identity) {
				os_free(identity);
				identity = NULL;
			}
			return FALSE;
		}

		if (imsi == NULL) {
			wpa_printf(MSG_INFO, "IMSI not available, return\n");
			if (eap_auth_start.eap_meta_id != NULL) {
				os_free(eap_auth_start.eap_meta_id);
				eap_auth_start.eap_meta_id = NULL;
			}
			if (eap_auth_start.user_id != NULL) {
				os_free(eap_auth_start.user_id);
				eap_auth_start.user_id = NULL;
			}
			if (NULL != identity) {
				os_free(identity);
				identity = NULL;
			}
			return FALSE;
		} else {
			wpa_printf(MSG_ERROR, "IMSI not NULL \n");
			if (NULL == identity)
				wpa_printf(MSG_ERROR, "config file doesn't contain identity \n");
			else
				wpa_printf(MSG_ERROR, "config file contains identity \n");

			wpa_printf(MSG_ERROR, "eap_type: %d\n", eap_proxy->eap_type);

			if (!idx) {

				/* IMSI is expected as username */
				wpa_printf(MSG_ERROR, " username is not available in config picking IMSI \n");

				if (config->identity_len > 1)
					/* @realm provided in config */
					imsi_identity = os_malloc(1 + IMSI_LENGTH + config->identity_len);
				else if (identity_format == EAP_IDENTITY_IMSI_3GPP_REALM)
					/* IMSI@realm not provided through config */
					imsi_identity = os_malloc(1 + IMSI_LENGTH + os_strlen(realm_3gpp));
				else
					/* IMSI RAW */
					imsi_identity = os_malloc(1 + IMSI_LENGTH);

				if (NULL == imsi_identity) {
					wpa_printf(MSG_ERROR, "Memory not available\n");
					if (eap_auth_start.eap_meta_id != NULL) {
						os_free(eap_auth_start.eap_meta_id);
						eap_auth_start.eap_meta_id = NULL;
					}
					if (eap_auth_start.user_id != NULL) {
						os_free(eap_auth_start.user_id);
						eap_auth_start.user_id = NULL;
					}
					if (NULL != identity) {
						os_free(identity);
						identity = NULL;
					}
					return FALSE;
				} else {
					if (config->identity_len > 1)
						os_memset(imsi_identity, 0, (1 + IMSI_LENGTH + config->identity_len));
					else if (identity_format == EAP_IDENTITY_IMSI_3GPP_REALM)
						os_memset(imsi_identity, 0, (1 + IMSI_LENGTH + os_strlen(realm_3gpp)));
					else
						os_memset(imsi_identity, 0, (1 + IMSI_LENGTH));

					if (eap_proxy->eap_type == EAP_TYPE_SIM)
						imsi_identity[0] = '1';
					else if (eap_proxy->eap_type == EAP_TYPE_AKA)
						imsi_identity[0] = '0';
#ifdef CONFIG_EAP_PROXY_AKA_PRIME
					else if (eap_proxy->eap_type == EAP_TYPE_AKA_PRIME)
						imsi_identity[0] = '6';
#endif /* CONFIG_EAP_PROXY_AKA_PRIME */
					else
						/* Default value is set as SIM */
						imsi_identity[0] = '1';

					/* copying IMSI value */
					os_memcpy(imsi_identity + 1 , imsi , imsi_len_g);

					if (config->identity_len > 1 && NULL != identity) {
						/* copying realm tag */
						os_memcpy(imsi_identity + 1 + imsi_len_g , identity , config->identity_len);
						imsi_id_len = imsi_len_g + 1 + config->identity_len;
						os_free(identity);
						identity = NULL;
					} else if (identity_format == EAP_IDENTITY_IMSI_3GPP_REALM) {
						/* realm is not available so append it */
						os_memcpy(imsi_identity + 1 + imsi_len_g , realm_3gpp, os_strlen(realm_3gpp));
						imsi_id_len = imsi_len_g + 1 + os_strlen(realm_3gpp);
					} else
						/* IMSI RAW */
						imsi_id_len = imsi_len_g + 1;
				}
			} else {
				/* idx is non-zero implies username available */
				imsi_identity = identity;
				imsi_id_len = config->identity_len;
			}
		}

		if (identity_format == EAP_IDENTITY_IMSI_3GPP_REALM || mcc_idx) {

			if (0 == idx) {
			/* id = @wlan.mnc000.mcc000.<>.<> realm exist
				but need to insert mnc and mcc values */
				idx = imsi_len_g + 1;
			}

			/* mcc valus */
			imsi_identity[idx + 16] = imsi[0];
			imsi_identity[idx + 17] = imsi[1];
			imsi_identity[idx + 18] = imsi[2];

			/* mnc valus */
			mnc_len = card_mnc_len;
			wpa_printf(MSG_ERROR, "card mnc len %d\n", card_mnc_len);

			if (mnc_len < 0) {
				wpa_printf(MSG_INFO, "Failed to get MNC length from (U)SIM "
				"assuming 3 in build_id");
				mnc_len = 3;
			}

			if (mnc_len == 2) {
				imsi_identity[idx + 9]  = '0';
				imsi_identity[idx + 10] = imsi[3];
				imsi_identity[idx + 11] = imsi[4];
			} else if (mnc_len == 3) {
				imsi_identity[idx + 9]  = imsi[3];
				imsi_identity[idx + 10] = imsi[4];
				imsi_identity[idx + 11] = imsi[5];
			}
			wpa_printf(MSG_ERROR, " Appending 3gpp realm\n ");
		}
		identity = imsi_identity;
		identity_len = imsi_id_len;
		eap_auth_start.params_mask |= QMI_EAP_AUTH_START_EAP_USER_ID_PARAM;
	}

	eap_auth_start.user_id_len = identity_len;
	eap_auth_start.user_id = identity;
	eap_auth_start.params_mask |= QMI_EAP_AUTH_START_EAP_USER_ID_PARAM;

	wpa_printf(MSG_ERROR, " eap auth user identity  - %20s length-%d\n ",
		    eap_auth_start.user_id, eap_auth_start.user_id_len);

	if ( (sim_num < 0) || (sim_num >= MAX_NO_OF_SIM_SUPPORTED)) {
		wpa_printf(MSG_ERROR, "eap_proxy: SIM: Invalid SIM selected by "
			    "User: Selected sim = %d\n", sim_num+1);
		return FALSE;
	}

	if (0 >= eap_proxy->qmihandle[sim_num]) {
		wpa_printf(MSG_ERROR, "eap_proxy: Failed to get the qmihandle "
			    "(value = %d) for the Sim %d\n",
			    eap_proxy->qmihandle[sim_num], sim_num+1);
		return FALSE;
	}

        eap_proxy->user_selected_sim = sim_num;
	wpa_printf(MSG_ERROR, "eap_proxy: SIM selected by User: Selected sim = %d\n",
		    eap_proxy->user_selected_sim+1);
	wpa_printf (MSG_ERROR, "eap_proxy: in eap_proxy_build_identity qmihandle[%d] = %d\n",
		     sim_num, eap_proxy->qmihandle[sim_num]);
#ifdef CONFIG_EAP_PROXY_DUAL_SIM
	if (sim_num == 0) {
		qmiRetCode = qmi_auth_set_subscription_binding(eap_proxy->qmihandle[sim_num],
							QMI_AUTH_SUBS_TYPE_PRIMARY,
							&qmiErrorCode);
		if (QMI_NO_ERR != qmiRetCode) {
			wpa_printf(MSG_ERROR, "Unable to get the qmi_auth_set_subscription_binding for"
					" sim 1; error_ret=%d; error_code=%d\n", qmiRetCode,
					qmiErrorCode);
			return FALSE;
		}
		wpa_printf (MSG_ERROR, "Binded with PRIMARY Subscription\n");
	} else if (sim_num == 1) {
		qmiRetCode = qmi_auth_set_subscription_binding(eap_proxy->qmihandle[sim_num],
							QMI_AUTH_SUBS_TYPE_SECONDARY,
							&qmiErrorCode);
		if (QMI_NO_ERR != qmiRetCode) {
			wpa_printf(MSG_ERROR, "Unable to get the qmi_auth_bind_subscription for sim 2;"
					" error_ret=%d; error_code=%d\n", qmiRetCode,
					qmiErrorCode);
			return FALSE;
		}
		wpa_printf (MSG_ERROR, "Binded with SECONDARY Subscription\n");
	} else {
		wpa_printf(MSG_ERROR, "Invalid SIM selected by User: Selected sim = %d\n", sim_num+1);
		return FALSE;
	}
#endif
	if (TRUE == eap_auth_session_flag[sim_num]) {
		if (eap_proxy->qmihandle[sim_num] != 0) {
			qmiRetCode = qmi_eap_auth_end_eap_session(eap_proxy->qmihandle[sim_num],
									&qmiErrorCode);
			if (QMI_NO_ERR != qmiRetCode) {
				wpa_printf(MSG_ERROR, "Unable to end the EAP session;"
						" error_ret=%d; error_code=%d\n", qmiRetCode,
						qmiErrorCode);
			}
			eap_auth_session_flag[sim_num] = FALSE;
		}
	}

	if (FALSE == eap_auth_session_flag[sim_num]) {
		if (eap_proxy->qmihandle[sim_num] != 0) {
			wpa_printf(MSG_ERROR, "eap_proxy: qmihandle[%d] = %d\n", sim_num, eap_proxy->qmihandle[sim_num]);
			wpa_printf(MSG_ERROR, "eap_auth_start values\n");
			wpa_printf(MSG_ERROR, "eap_auth_start.eap_method_mask = %ld\n", eap_auth_start.eap_method_mask);
			wpa_printf(MSG_ERROR, "eap_auth_start.user_id_len = %d\n", eap_auth_start.user_id_len);
			wpa_printf(MSG_ERROR, "eap_auth_start.eap_meta_id_len = %d\n", eap_auth_start.eap_meta_id_len);
			wpa_printf(MSG_ERROR, "eap_auth_start.eap_sim_aka_algo = %d\n", eap_auth_start.eap_sim_aka_algo);
			qmiRetCode = qmi_eap_auth_start_eap_session_ex(eap_proxy->qmihandle[sim_num],
								&eap_auth_start, &qmiErrorCode);
			if (QMI_NO_ERR != qmiRetCode) {
				wpa_printf(MSG_ERROR, "Unable to start the EAP session;"
						" error_ret=%d; error_code=%d\n", qmiRetCode,
						qmiErrorCode);
				return FALSE;
			}
			eap_auth_session_flag[sim_num] = TRUE;
			eap_proxy->qmi_state = QMI_STATE_IDLE;
			if (NULL != eap_auth_start.user_id) {
				os_free (eap_auth_start.user_id);
				eap_auth_start.user_id = NULL;
			}
			if (NULL != eap_auth_start.eap_meta_id) {
				os_free (eap_auth_start.eap_meta_id);
				eap_auth_start.eap_meta_id = NULL;
			}
			wpa_printf(MSG_ERROR, "EAP session started"
					" error_ret=%d; error_code=%d\n", qmiRetCode,
					qmiErrorCode);
		}
	}

	return TRUE;
}



#ifdef CONFIG_CTRL_IFACE

/**
 * eap_proxyl_sm_get_status - Get EAP state machine status
 * @sm: Pointer to EAP state machine allocated with eap_sm_init()
 * @buf: Buffer for status information
 * @buflen: Maximum buffer length
 * @verbose: Whether to include verbose status information
 * Returns: Number of bytes written to buf.
 *
 * Query EAP state machine for status information. This function fills in a
 * text area with current status information from the EAPOL state machine. If
 * the buffer (buf) is not large enough, status information will be truncated
 * to fit the buffer.
 */
int eap_proxy_sm_get_status(struct eap_proxy_sm *sm, char *buf, size_t buflen,
			    int verbose)
{
	int len, ret;

	if (sm == NULL)
		return 0;

	len = os_snprintf(buf, buflen, "EAP state=%s\n",
			  eap_proxy_sm_state_txt(sm->proxy_state));
	if (len < 0 || (size_t)len >= buflen)
		return 0;

	if (sm->eap_type != EAP_TYPE_NONE) {
		char name[8] = "Unknown";

	if (sm->eap_type == EAP_TYPE_SIM)
		os_strlcpy(name, "SIM", 4);
	else if (sm->eap_type == EAP_TYPE_AKA)
		os_strlcpy(name, "AKA", 4);

		ret = os_snprintf(buf + len, buflen - len,
				"selectedMethod=%d (EAP-%s)\n",
					sm->eap_type, name);
		if (ret < 0 || (size_t)ret >= buflen - len)
			return len;
		len += ret;
	}

	return len;
}


static const char *eap_proxy_sm_state_txt(int state)
{
	switch (state) {
	case EAP_PROXY_INITIALIZE:
		return "INITIALIZE";
	case EAP_PROXY_DISABLED:
		return "DISABLED";
	case EAP_PROXY_IDLE:
		return "IDLE";
	case EAP_PROXY_RECEIVED:
		return "RECEIVED";
	case EAP_PROXY_GET_METHOD:
		return "GET_METHOD";
	case EAP_PROXY_METHOD:
		return "METHOD";
	case EAP_PROXY_SEND_RESPONSE:
		return "SEND_RESPONSE";
	case EAP_PROXY_DISCARD:
		return "DISCARD";
	case EAP_PROXY_IDENTITY:
		return "IDENTITY";
	case EAP_PROXY_NOTIFICATION:
		return "NOTIFICATION";
	case EAP_PROXY_RETRANSMIT:
		return "RETRANSMIT";
	case EAP_PROXY_AUTH_SUCCESS:
		return "SUCCESS";
	case EAP_PROXY_AUTH_FAILURE:
		return "FAILURE";
	default:
		return "UNKNOWN";
	}
}
#endif /* CONFIG_CTRL_IFACE */


/**
 * eap_proxy_get_mcc_mnc - Get MCC/MNC
 * @imsi_buf: Buffer for returning IMSI
 * @imsi_len: Buffer for returning IMSI length
 * Returns: MNC length (2 or 3) or -1 on error
 */
int eap_proxy_get_imsi(struct eap_proxy_sm *eap_proxy, char *imsi_buf,
			size_t *imsi_len)
{
#ifdef SIM_AKA_IDENTITY_IMSI
	int mnc_len;
	int sim_num = eap_proxy->user_selected_sim;

	if (!wpa_qmi_read_card_status(sim_num)) {
	wpa_printf(MSG_INFO, "eap_proxy: Card not ready");
		return -1;
	}

	if (!wpa_qmi_read_card_imsi(sim_num) || imsi == NULL) {
		wpa_printf(MSG_INFO, "eap_proxy: Failed to read card IMSI");
		return -1;
	}

	*imsi_len = os_strlen(imsi);
	os_memcpy(imsi_buf, imsi, *imsi_len + 1);

	mnc_len = card_mnc_len;
	if (mnc_len < 2 || mnc_len > 3)
		mnc_len = 3; /* Default to 3 if MNC length is unknown */

	os_free(imsi);
	imsi = NULL;

	return mnc_len;
#else /* SIM_AKA_IDENTITY_IMSI */
	return -1;
#endif /* SIM_AKA_IDENTITY_IMSI */
}

int eap_proxy_notify_config(struct eap_proxy_sm *eap_proxy,
                            struct eap_peer_config *config)
{
	int ret_val;

	wpa_printf(MSG_ERROR, "eap_proxy: eap_proxy_notify_config\n");
	if (!eap_proxy) {
		wpa_printf(MSG_ERROR, "eap_proxy: is NULL");
		return -1;
	}

	if ( config && eap_proxy_allowed_method(config, EAP_VENDOR_IETF,
			EAP_TYPE_SIM)) {
		eap_proxy->eap_type =  EAP_TYPE_SIM;
		ret_val = TRUE;
	} else if ( config && eap_proxy_allowed_method(config, EAP_VENDOR_IETF,
	                        EAP_TYPE_AKA)) {
		eap_proxy->eap_type =  EAP_TYPE_AKA;
		ret_val = TRUE;
	} else if ( config && eap_proxy_allowed_method(config, EAP_VENDOR_IETF,
	                        EAP_TYPE_AKA_PRIME)) {
		eap_proxy->eap_type =  EAP_TYPE_AKA_PRIME;
		ret_val = TRUE;
	} else
		ret_val = FALSE;

	return ret_val;
}

int eap_proxy_allowed_method (struct eap_peer_config *config, int vendor,
			      u32 method)
{
	int i;
	struct eap_method_type *m;

	wpa_printf(MSG_ERROR, "eap_proxy: eap_proxy_allowed_method");
	if (config == NULL || config->eap_methods == NULL)
		return -1;

	m = config->eap_methods;
	for (i = 0; m[i].vendor != EAP_VENDOR_IETF ||
		     m[i].method != EAP_TYPE_NONE; i++) {
		if (m[i].vendor == vendor && m[i].method == method)
			return 1;
	}
	return 0;
}

#endif  /* CONFIG_EAP_PROXY */
