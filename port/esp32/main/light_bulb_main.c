/* lightbulb damon task

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"

#include "debug_print.h"
#include "lightbulb.h"

void lightbulb_damon_task(void *pvParameter)
{
    APP_DBG("start lightbulb damon task...");
    lightbulb_init();
    bulb_state_t *esp_bulb_current_state = NULL;

    while (1) {
        esp_bulb_current_state = get_current_bulb_state();
        APP_DBG("[update] on/off:%d interval:%d H:%f S:%f B:%d", \
                 esp_bulb_current_state->set_on, esp_bulb_current_state->flash_interval, \
                 esp_bulb_current_state->hue_value, esp_bulb_current_state->saturation_value, esp_bulb_current_state->brightness_value);

        // set light state to GPIO
        lightbulb_set_hue(&(esp_bulb_current_state->hue_value));
        lightbulb_set_saturation(&(esp_bulb_current_state->saturation_value));
        lightbulb_set_brightness(&(esp_bulb_current_state->brightness_value));
        lightbulb_set_on(&(esp_bulb_current_state->set_on));

        vTaskDelay(10 / portTICK_RATE_MS);

        // flash or not
        if (esp_bulb_current_state->flash_interval != 0) {
            lightbulb_set_off();
            vTaskDelay(esp_bulb_current_state->flash_interval);
        }
    }

    (void)vTaskDelete(NULL);
}
