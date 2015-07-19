/* Copyright (c) 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef OVN_LFLOW_H
#define OVN_LFLOW_H 1

/* Logical_Flow table translation to OpenFlow
 * ==========================================
 *
 * The Logical_Flow table obtained from the OVN_Southbound database works in
 * terms of logical entities, that is, logical flows among logical datapaths
 * and logical ports.  This code translates these logical flows into OpenFlow
 * flows that, again, work in terms of logical entities implemented through
 * OpenFlow extensions (e.g. registers represent the logical input and output
 * ports).
 *
 * Physical-to-logical and logical-to-physical translation are implemented in
 * physical.[ch] as separate OpenFlow tables that run before and after,
 * respectively, the logical pipeline OpenFlow tables.
 */

#include <stdint.h>

struct controller_ctx;
struct hmap;
struct uuid;

/* Logical fields. */
#define MFF_LOG_DATAPATH MFF_METADATA /* Logical datapath (64 bits). */
#define MFF_LOG_INPORT   MFF_REG6     /* Logical input port (32 bits). */
#define MFF_LOG_OUTPORT  MFF_REG7     /* Logical output port (32 bits). */

void lflow_init(void);
void lflow_run(struct controller_ctx *, struct hmap *flow_table);
void lflow_destroy(void);

uint32_t ldp_to_integer(const struct uuid *logical_datapath);

#endif /* ovn/lflow.h */
