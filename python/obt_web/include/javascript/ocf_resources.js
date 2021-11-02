
/*These devices have a valid image 
 * /include/images
 * */
var images = [
	'oic.d.diplomat',
	'oic.d.light',
	'oic.d.phone',
	'oic.d.speaker'
]

/*Input device
 * Returns: array of device types
 * */
function get_device_types(device){
	var device_types =[];
	for (resource in device.resources){
		if(device.resources[resource].uri.includes("/oic/d")){
			for(type_index in device.resources[resource].types){
				if(!device.resources[resource].types[type_index].includes("oic.wk.d")){
					device_types.push(device.resources[resource].types[type_index]);
				}
			}
		}
	}
	return(device_types)
}

/*Input device
 * Returns: array of non-oic resurces
 * */
function get_non_oic_resources(device){
		var non_oic_resources = [];
		for (resource in device.resources){
			/*Non OIC resources*/
			if (!device.resources[resource].uri.includes("/oic") && !device.resources[resource].uri.includes("/oc")){
					for (non_oic_resource in device.resources[resource].types){
						if(!non_oic_resources.includes(device.resources[resource].types[non_oic_resource])){
							non_oic_resources.push(device.resources[resource].types[non_oic_resource]);
						}
					}
			}
		}
	return(non_oic_resources)
}

function control_change(source_control,device_type,cmd,device_uuid){
	resource = $("#resource_select_"+device_uuid).val();
	send_command(source_control,device_type,cmd,resource);

}

/*Returns: HTML based controls depending on the device type
 * */
function return_client_controls(device){

	var device_types = get_device_types(device);	
	var client_controls = "";
	var non_oic = get_non_oic_resources(device);
	for(type_index in device_types){
		device_type = device_types[type_index];
		switch(device_type){
		case "oic.d.light":
			var resources="";
			var cmd = 'post';
			resources +="<p>Resources</p>";
			resources +="<select id=resource_select_"+device.uuid+">";
			//These are non OIC resources
			for (non_index in non_oic){
				resources += "<option value="+non_oic[non_index]+">"+non_oic[non_index]+"</option>"; 
			}
			resources +="</select>";
			client_controls += `
			 <div>Device Type: `+device_type+`</div>
			 `+resources+`
			  <div style="margin:5px">
			  	 <p>Controls</p>
				  <label class="switch">
				  <input type="checkbox" id='switch_`+device.uuid+`' onchange=control_change(this,'`+device_type+`','`+cmd+`','`+device.uuid+`')>
				  <span class="slider round"></span>
				</label>
			  </div>
			`;
			continue;
		case "oic.d.diplomat":
			client_controls += `
			 <div>Streamlined Onboarding</div>
			  <div>
				<label class="switch">
				  <input type="checkbox" id='switch_so' onchange=observe_diplomat(this)>
				  <span class="slider round"></span>
				</label>
			  </div>
			`;
			break;
		default:
			client_controls = `
			<div class='no_resource'>
				No resources returned
				</div>
			`;
			break;

		}
	}

	return (client_controls);

}
/*
 *
	  <p>
		 /a/light
	  </p>
		  <label class="switch">
		  <input type="checkbox" id='switch_`+uuid+`' onchange=send_command(this)>
		  <span class="slider round"></span>
		</label>
	  </p>
	  <p>
	  /a/brightlight
	  </p>
	  <p>
		<div class="slidecontainer">
		  <input type="range" min="1" max="100" value="50">
		</div>
	  </p>
	  */
