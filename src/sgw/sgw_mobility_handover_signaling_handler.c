/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file sgw_handlers.c
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/
#define SGW
#define SGW_MOBILITY_HANDOVER_SIGNALLING_HANDLERS_C

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>

#include "bstrlib.h"

#include "dynamic_memory_check.h"
#include "assertions.h"
#include "conversions.h"
#include "hashtable.h"
#include "obj_hashtable.h"
#include "common_defs.h"
#include "intertask_interface.h"
#include "msc.h"
#include "log.h"
#include "sgw_ie_defs.h"
#include "3gpp_23.401.h"
#include "common_types.h"
#include "mme_config.h"
#include "sgw_defs.h"
#include "sgw_handlers.h"
#include "sgw_context_manager.h"
#include "sgw.h"
#include "pgw_lite_paa.h"
#include "pgw_pco.h"
#include "spgw_config.h"
#include "gtpv1u.h"
#include "pgw_ue_ip_address_alloc.h"
#include "pgw_pcef_emulation.h"
#include "sgw_context_manager.h"
#include "pgw_procedures.h"
#include "async_system.h"
#include "sgw_handover_signaling_handler.h"

extern sgw_app_t                        sgw_app;
extern spgw_config_t                    spgw_config;
extern struct gtp_tunnel_ops           *gtp_tunnel_ops;
static uint32_t                         g_gtpv1u_teid = 0;

int
sgw_handle_mobility_sgi_endpoint_updated (
  const itti_sgi_update_end_point_response_t * const resp_pP, teid_t enb_teid_S1u_src)
{
  OAILOG_FUNC_IN(LOG_SPGW_APP);
  itti_s11_modify_bearer_response_t      *modify_response_p = NULL;
  s_plus_p_gw_eps_bearer_context_information_t *new_bearer_ctxt_info_p = NULL;
  MessageDef                             *message_p = NULL;
  sgw_eps_bearer_ctxt_t                  *eps_bearer_ctxt_p = NULL;
  hashtable_rc_t                          hash_rc = HASH_TABLE_OK;
  hashtable_rc_t                          hash_rc2 = HASH_TABLE_OK;
  int                                     rv = RETURNok;
  mme_sgw_tunnel_t                       *tun_pair_p = NULL;


  OAILOG_DEBUG (LOG_SPGW_APP, "Rx SGI_UPDATE_ENDPOINT_RESPONSE, Context teid " TEID_FMT " Tunnel " TEID_FMT " (eNB) <-> (SGW) " TEID_FMT " EPS bearer id %u, status %d\n",
                  resp_pP->context_teid, resp_pP->enb_S1u_teid, resp_pP->sgw_S1u_teid, resp_pP->eps_bearer_id, resp_pP->status);
  message_p = itti_alloc_new_message (TASK_SPGW_APP, S11_MODIFY_BEARER_RESPONSE);

  if (!message_p) {
    OAILOG_FUNC_RETURN(LOG_SPGW_APP,  RETURNerror);
  }

  modify_response_p = &message_p->ittiMsg.s11_modify_bearer_response;
  hash_rc = hashtable_ts_get (sgw_app.s11_bearer_context_information_hashtable, resp_pP->context_teid, (void **)&new_bearer_ctxt_info_p);
  hash_rc2 = hashtable_ts_get (sgw_app.s11teid2mme_hashtable, resp_pP->context_teid /*local teid*/, (void **)&tun_pair_p);

  if ((HASH_TABLE_OK == hash_rc) && (HASH_TABLE_OK == hash_rc2)) {
    eps_bearer_ctxt_p =
        sgw_cm_get_eps_bearer_entry(&new_bearer_ctxt_info_p->sgw_eps_bearer_context_information.pdn_connection,
            resp_pP->eps_bearer_id);

   if (NULL == eps_bearer_ctxt_p) {
      OAILOG_DEBUG (LOG_SPGW_APP, "Rx SGI_UPDATE_ENDPOINT_RESPONSE: CONTEXT_NOT_FOUND (pdn_connection. context)\n");

      modify_response_p->teid = tun_pair_p->remote_teid;
      modify_response_p->bearer_contexts_marked_for_removal.bearer_contexts[0].eps_bearer_id = resp_pP->eps_bearer_id;
      modify_response_p->bearer_contexts_marked_for_removal.bearer_contexts[0].cause.cause_value = CONTEXT_NOT_FOUND;
      modify_response_p->bearer_contexts_marked_for_removal.num_bearer_context += 1;
      modify_response_p->cause.cause_value = CONTEXT_NOT_FOUND;
      modify_response_p->trxn = 0;
      MSC_LOG_TX_MESSAGE (MSC_SP_GWAPP_MME, MSC_S11_MME,
                          NULL, 0, "0 S11_MODIFY_BEARER_RESPONSE ebi %u CONTEXT_NOT_FOUND trxn %u",
                          modify_response_p->bearer_contexts_marked_for_removal.bearer_contexts[0].eps_bearer_id,
                          modify_response_p->trxn);
      rv = itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
      OAILOG_FUNC_RETURN(LOG_SPGW_APP, rv);
  } else if (HASH_TABLE_OK == hash_rc) {
      OAILOG_DEBUG (LOG_SPGW_APP, "Rx SGI_UPDATE_ENDPOINT_RESPONSE: REQUEST_ACCEPTED\n");
      // accept anyway
      modify_response_p->teid = tun_pair_p->remote_teid;
      modify_response_p->bearer_contexts_modified.bearer_contexts[0].eps_bearer_id = resp_pP->eps_bearer_id;
      modify_response_p->bearer_contexts_modified.bearer_contexts[0].cause.cause_value = REQUEST_ACCEPTED;
      modify_response_p->bearer_contexts_modified.num_bearer_context += 1;
      modify_response_p->cause.cause_value = REQUEST_ACCEPTED;
      modify_response_p->trxn = new_bearer_ctxt_info_p->sgw_eps_bearer_context_information.trxn;
      // if default bearer
      //#pragma message  "TODO define constant for default eps_bearer id"

      // setup GTPv1-U tunnel
      struct in_addr t_enb = {.s_addr = 0};
      t_enb.s_addr = eps_bearer_ctxt_p->enb_ip_address_S1u.address.ipv4_address.s_addr;

      struct in_addr ue = {.s_addr = 0};
      ue.s_addr = eps_bearer_ctxt_p->paa.ipv4_address.s_addr;

      if (spgw_config.pgw_config.use_gtp_kernel_module) {
        rv = gtp_tunnel_ops->del_tunnel(eps_bearer_ctxt_p->s_gw_teid_S1u_S12_S4_up, enb_teid_S1u_src);
        if (rv < 0) {
          OAILOG_ERROR (LOG_SPGW_APP, "ERROR in setting up TUNNEL err=%d\n", rv);
        }
        rv = gtp_tunnel_ops->add_tunnel(ue, t_enb, eps_bearer_ctxt_p->s_gw_teid_S1u_S12_S4_up, eps_bearer_ctxt_p->enb_teid_S1u);
        if (rv < 0) {
          OAILOG_ERROR (LOG_SPGW_APP, "ERROR in setting down TUNNEL err=%d\n", rv);
        }

      }
    }

    MSC_LOG_TX_MESSAGE (MSC_SP_GWAPP_MME, MSC_S11_MME, NULL, 0, "0 S11_MODIFY_BEARER_RESPONSE ebi %u  trxn %u",
        modify_response_p->bearer_contexts_modified.bearer_contexts[0].eps_bearer_id, modify_response_p->trxn);
    rv = itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
    OAILOG_FUNC_RETURN(LOG_SPGW_APP, rv);
  } else {
    if (HASH_TABLE_OK != hash_rc2) {
      OAILOG_DEBUG (LOG_SPGW_APP, "Rx SGI_UPDATE_ENDPOINT_RESPONSE: CONTEXT_NOT_FOUND (S11 context)\n");
      modify_response_p->teid = resp_pP->context_teid;    
      modify_response_p->bearer_contexts_marked_for_removal.bearer_contexts[0].eps_bearer_id = resp_pP->eps_bearer_id;
      modify_response_p->bearer_contexts_marked_for_removal.bearer_contexts[0].cause.cause_value = CONTEXT_NOT_FOUND;
      modify_response_p->bearer_contexts_marked_for_removal.num_bearer_context += 1;
      modify_response_p->cause.cause_value = CONTEXT_NOT_FOUND;
      modify_response_p->trxn = 0;
      MSC_LOG_TX_MESSAGE (MSC_SP_GWAPP_MME,  MSC_S11_MME,
                        NULL, 0, "0 S11_MODIFY_BEARER_RESPONSE ebi %u CONTEXT_NOT_FOUND trxn %u",
                        modify_response_p->bearer_contexts_marked_for_removal.bearer_contexts[0].eps_bearer_id, modify_response_p->trxn);
      rv = itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
      OAILOG_FUNC_RETURN(LOG_SPGW_APP, rv);
    } else {
      OAILOG_FUNC_RETURN(LOG_SPGW_APP, RETURNerror);
    }
  }
}

