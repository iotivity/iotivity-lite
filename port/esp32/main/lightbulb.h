/*  Lightbulb interface

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#ifndef LIGHTBULB_H_
#define LIGHTBULB_H_

typedef enum {
    BULB_STATE_OFF = 0,
    BULB_STATE_RED = 1,
    BULB_STATE_GREEN = 2,
    BULB_STATE_BLUE = 3,
    BULB_STATE_OTHERS = 4
} bulb_color_t;

typedef struct bulb_state {
    bool set_on;
    double hue_value;
    double saturation_value;
    int brightness_value;
    int flash_interval;
} bulb_state_t;

/**
 * @brief initialize the lightbulb lowlevel module
 *
 * @param none
 *
 * @return none
 */
void lightbulb_init(void);

/**
 * @brief deinitialize the lightbulb's lowlevel module
 *
 * @param none
 *
 * @return none
 */
void lightbulb_deinit(void);

/**
 * @brief turn on/off the lowlevel lightbulb
 *
 * @param p signal point, the data is type of "bool"
 *
 * @return none
 */
void lightbulb_set_on(void *p);

/**
 * @brief set the saturation of the lowlevel lightbulb
 *
 * @param p signal point, the data is type of "int"
 *
 * @return
 *     - 0 : OK
 *     - others : fail
 */
void lightbulb_set_saturation(void *p);

/**
 * @brief set the hue of the lowlevel lightbulb
 *
 * @param p signal point, the data is type of "double"
 *
 * @return
 *     - 0 : OK
 *     - others : fail
 */
void lightbulb_set_hue(void *p);

/**
 * @brief set the brightness of the lowlevel lightbulb
 *
 * @param p signal point, the data is type of "double"
 *
 * @return
 *     - 0 : OK
 *     - others : fail
 */
void lightbulb_set_brightness(void *p);

/**
 * @brief  notify light state to set, time interval to set
 *
 * @param[in] state state to set
 * @param[in] time interval to set
 *
 * @return  noreturn
 *
 * */
void notify_lightbulb_state(bulb_color_t in_color, int flash_interval);

/**
 * @brief get current light state
 *
 * @param[in]  in parameter input
 *
 * @return  struct bulb_state_t which including light state
 * */
bulb_state_t *get_current_bulb_state();

/**
 * @brief set current light state
 *
 * @param[in]  input_save_bulb_state: struct bulb_state_t which including light state
 *
 * @return  noreturn
 * */
void set_current_bulb_state(bulb_state_t input_save_bulb_state);

/**
 * @brief  set light state off
 *
 * @param[in]  no parameter input
 *
 * @return  noreturn
 *
 * */
void lightbulb_set_off();

// main light state damon task
void lightbulb_damon_task(void *pvParameter);

#endif /* LIGHTBULB_H_ */
