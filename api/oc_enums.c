/*
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <stdio.h>
#include "oc_enums.h"

static const char *pos_desc[] = { "unknown",     "top",         "bottom",
                                  "left",        "right",       "centre",
                                  "topleft",     "bottomleft",  "centreleft",
                                  "centreright", "bottomright", "topright",
                                  "topcentre",   "bottomcentre" };

static const char *oc_enums[] = { "aborted",
                                  "active",
                                  "airDry",
                                  "armedAway",
                                  "armedInstant",
                                  "armedMaximum",
                                  "armedNightStay",
                                  "armedStay",
                                  "aroma",
                                  "artificalintelligence",
                                  "auto",
                                  "boiling",
                                  "brewing",
                                  "cancelled",
                                  "circulating",
                                  "cleaning",
                                  "clothes",
                                  "completed",
                                  "cool",
                                  "delicate",
                                  "disabled",
                                  "down",
                                  "dual",
                                  "dry",
                                  "enabled",
                                  "extended",
                                  "fan",
                                  "fast",
                                  "filterMaterial",
                                  "focused",
                                  "grinding",
                                  "heating",
                                  "heavy",
                                  "idle",
                                  "ink",
                                  "inkBlack",
                                  "inkCyan",
                                  "inkMagenta",
                                  "inkTricolour",
                                  "inkYellow",
                                  "keepwarm",
                                  "normal",
                                  "notsupported",
                                  "pause",
                                  "pending",
                                  "pendingHeld",
                                  "permapress",
                                  "preWash",
                                  "processing",
                                  "pure",
                                  "quick",
                                  "quiet",
                                  "rinse",
                                  "sectored",
                                  "silent",
                                  "sleep",
                                  "smart",
                                  "spot",
                                  "steam",
                                  "stopped",
                                  "spin",
                                  "testing",
                                  "toner",
                                  "tonerBlack",
                                  "tonerCyan",
                                  "tonerMagenta",
                                  "tonerYellow",
                                  "warm",
                                  "wash",
                                  "wet",
                                  "wind",
                                  "wrinklePrevent",
                                  "zigzag" };

static const char *oc_locns[] = {
                                  "unknown",       
								  "attic",        
								  "balcony",
                                  "ballroom",      
								  "bathroom",     
								  "bedroom",
                                  "border",        
								  "boxroom",      
								  "cellar",
                                  "cloakroom",     
								  "conservatory", 
								  "corridor",
                                  "deck",          
								  "den",          
								  "diningroom",
                                  "drawingroom",   
								  "driveway",     
								  "dungeon",
                                  "ensuite",       
								  "entrance",     
								  "familyroom",
                                  "garage",        
								  "garden",       
								  "guestroom",
                                  "hall",          
								  "indoor",       
								  "kitchen",
                                  "larder",        
								  "lawn",         
								  "library",
                                  "livingroom",    
								  "lounge",       
								  "mancave",
                                  "masterbedroom", 
								  "musicroom",    
								  "office",
                                  "outdoor",       
								  "pantry",       
								  "parkinglot",
                                  "parlour",       
								  "patio",        
								  "receiptionroom",
                                  "restroom",      
								  "roof",         
								  "roofterrace",
                                  "sauna",         
								  "scullery",     
								  "shed",
                                  "sittingroom",   
								  "snug",         
								  "spa",
                                  "studio",        
								  "suite",        
								  "swimmingpool",
                                  "terrace",       
								  "toilet",       
								  "utilityroom",
                                  "vegetableplot", 
								  "ward",         
								  "yard" }; 

const char *
oc_enum_to_str(oc_enum_t val)
{
  if (val <= (sizeof(oc_enums) / sizeof(char *))) {
    return oc_enums[val - 1];
  }
  return NULL;
}

const char *
oc_enum_pos_desc_to_str(oc_pos_description_t pos)
{
  if (pos <= (sizeof(pos_desc) / sizeof(char *))) {
    return pos_desc[pos - 1];
  }
  return NULL;
}

const char *
oc_enum_locn_to_str(oc_locn_t locn)
{
  if (locn <= (sizeof(oc_locns) / sizeof(char *))) {
    return oc_locns[locn - 1];
  }
  return NULL;
}

oc_locn_t
oc_str_to_enum_locn(oc_string_t locn_str, bool *oc_defined)
{
  oc_locn_t locn = OCF_LOCN_UNKNOWN;
  for (int i = 0; i < (int)(sizeof(oc_locns) / sizeof(char *)); i++) {
    if (strcmp(oc_string(locn_str), oc_locns[i]) == 0) {
      locn = i + 1;
      *oc_defined = true;
      break;
    }
  }
  return locn;
}