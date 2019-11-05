package org.iotivity.multideviceclient;

import android.app.AlertDialog;
import android.app.Dialog;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcPlatform;
import org.iotivity.oc.OcUtils;

import java.util.ArrayList;

public class MultiDeviceClientActivity extends AppCompatActivity {

    private static final String TAG = MultiDeviceClientActivity.class.getSimpleName();

    private Button discoverDevicesButton;
    private ListView listView;

    private AdapterView.OnItemClickListener deviceItemClickListener;
    private ArrayAdapter<OcfDeviceInfo> deviceArrayAdapter;

    ArrayList<OcfDeviceInfo> deviceList = new ArrayList<>();
    private final Object arrayAdapterSync = new Object();

    private OcPlatform ocPlatform;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        deviceItemClickListener = new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final OcfDeviceInfo deviceInfo = deviceArrayAdapter.getItem((int) id);
                if (deviceInfo != null) {
                    final String uuid = OCUuidUtil.uuidToString(deviceInfo.getUuid());
                    AlertDialog.Builder discoverResourcesDialogBuilder = new AlertDialog.Builder(MultiDeviceClientActivity.this);
                    discoverResourcesDialogBuilder.setTitle(R.string.discoveredResources);

                    ListView resourceListView = new ListView(MultiDeviceClientActivity.this);
                    ArrayList<String> resourceList = new ArrayList<>();
                    final ArrayAdapter<String> resourceAdapter = new ArrayAdapter<>(MultiDeviceClientActivity.this, android.R.layout.simple_list_item_1, android.R.id.text1, resourceList);
                    resourceListView.setAdapter(resourceAdapter);
                    discoverResourcesDialogBuilder.setView(resourceListView);

                    resourceAdapter.setNotifyOnChange(false);
                    for (OcfResourceInfo resourceInfo : deviceInfo.getResourceInfos()) {
                        resourceAdapter.add(resourceInfo.getAnchor() + resourceInfo.getUri());
                    }
                    resourceAdapter.setNotifyOnChange(true);

                    resourceAdapter.notifyDataSetChanged();

                    Dialog discoverResourcesDialog = discoverResourcesDialogBuilder.create();
                    discoverResourcesDialog.show();

                } else {
                    Log.w(TAG, "Uuid not found in list");
                }
            }
        };

        discoverDevicesButton = (Button) findViewById(R.id.discover_devices_button);
        discoverDevicesButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                deviceArrayAdapter.setNotifyOnChange(false);
                deviceArrayAdapter.clear();
                deviceArrayAdapter.setNotifyOnChange(true);

                new Thread(new Runnable() {
                    public void run() {
                        if (!OcUtils.doIPMulticast("/oic/d", null, new GetDeviceHandler(MultiDeviceClientActivity.this))) {
                            final String msg = "Failed to discover devices";
                            Log.d(TAG, msg);
                            runOnUiThread(new Runnable() {
                                public void run() {
                                    Toast.makeText(MultiDeviceClientActivity.this, msg, Toast.LENGTH_LONG).show();
                                }
                            });
                        }
                    }
                }).start();
            }
        });

        deviceArrayAdapter = new ArrayAdapter(this, android.R.layout.simple_list_item_2, android.R.id.text1, deviceList) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                View view = super.getView(position, convertView, parent);
                TextView text1 = (TextView) view.findViewById(android.R.id.text1);
                TextView text2 = (TextView) view.findViewById(android.R.id.text2);

                OcfDeviceInfo deviceInfo = deviceArrayAdapter.getItem(position);
                if (deviceInfo != null) {
                    text1.setText(OCUuidUtil.uuidToString(deviceList.get(position).getUuid()));
                    text2.setText("\t" + deviceList.get(position).getName());
                }
                return view;
            }
        };

        listView = (ListView) findViewById(R.id.list_view);
        listView.setAdapter(deviceArrayAdapter);
        listView.setOnItemClickListener(deviceItemClickListener);

        if (savedInstanceState == null) {
            // start first time only
            ocPlatform = OcPlatform.getInstance();
            InitHandler handler = new InitHandler(this, ocPlatform);
            ocPlatform.systemInit(handler);
        }
    }

    @Override
    protected void onDestroy() {
        Log.d(TAG, "Calling Shutdown.");
        ocPlatform.systemShutdown();
        super.onDestroy();
    }

    public void addDevice(OcfDeviceInfo deviceInfo) {
        synchronized (arrayAdapterSync) {
            deviceArrayAdapter.setNotifyOnChange(false);
            deviceArrayAdapter.add(deviceInfo);
            deviceArrayAdapter.setNotifyOnChange(true);
        }

        runOnUiThread(new Runnable() {
            public void run() {
                deviceArrayAdapter.notifyDataSetChanged();
            }
        });
    }
}
