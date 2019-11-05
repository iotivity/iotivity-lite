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
import android.widget.SimpleAdapter;
import android.widget.TextView;
import android.widget.Toast;

import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcPlatform;
import org.iotivity.oc.OcUtils;

import java.util.ArrayList;
import java.util.HashMap;

public class MultiDeviceClientActivity extends AppCompatActivity {

    private static final String TAG = MultiDeviceClientActivity.class.getSimpleName();

    private Button discoverDevicesButton;
    private ListView listView;

    private AdapterView.OnItemClickListener resourceItemClickListener;
    private ArrayAdapter<OcfResourceInfo> resourceArrayAdapter;

    private AdapterView.OnItemClickListener deviceItemClickListener;
    private ArrayAdapter<OcfDeviceInfo> deviceArrayAdapter;

    ArrayList<OcfDeviceInfo> deviceList = new ArrayList<>();
    private final Object arrayAdapterSync = new Object();

    private OcPlatform ocPlatform;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        resourceItemClickListener = new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                OcfResourceInfo resourceInfo = resourceArrayAdapter.getItem((int) id);
                if (resourceInfo != null) {
                    AlertDialog.Builder resourceDialogBuilder = new AlertDialog.Builder(MultiDeviceClientActivity.this);
                    resourceDialogBuilder.setTitle(resourceInfo.getAnchor() + resourceInfo.getUri());

                    ListView resourceDetailsListView = new ListView(MultiDeviceClientActivity.this);
                    final ArrayList<HashMap<String, String>> resourceDetailsList = new ArrayList<>();
                    final SimpleAdapter resourceDetailsAdapter = new SimpleAdapter(MultiDeviceClientActivity.this, resourceDetailsList, R.layout.resource_multi_line,
                            new String[]{"line1", "line2", "line3", "line4"},
                            new int[]{R.id.line_1, R.id.line_2, R.id.line_3, R.id.line_4});

                    resourceDetailsListView.setAdapter(resourceDetailsAdapter);
                    resourceDialogBuilder.setView(resourceDetailsListView);

                    ResourceDetailsHelper.buildResourceDetails(resourceInfo, resourceDetailsList);

                    Dialog resourceDialog = resourceDialogBuilder.create();
                    resourceDialog.show();

                } else {
                    Log.w(TAG, "Resource not found in list");
                }
            }
        };

        deviceItemClickListener = new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                OcfDeviceInfo deviceInfo = deviceArrayAdapter.getItem((int) id);
                if (deviceInfo != null) {
                    AlertDialog.Builder discoverResourcesDialogBuilder = new AlertDialog.Builder(MultiDeviceClientActivity.this);
                    discoverResourcesDialogBuilder.setTitle(R.string.discoveredResources);

                    ListView resourceListView = new ListView(MultiDeviceClientActivity.this);
                    final ArrayList<OcfResourceInfo> resourceArrayList = new ArrayList<>();
                    resourceArrayAdapter = new ArrayAdapter(MultiDeviceClientActivity.this, android.R.layout.simple_list_item_1, android.R.id.text1, resourceArrayList) {
                        @Override
                        public View getView(int position, View convertView, ViewGroup parent) {
                            View view = super.getView(position, convertView, parent);
                            TextView text1 = (TextView) view.findViewById(android.R.id.text1);

                            OcfResourceInfo resourceInfo = resourceArrayAdapter.getItem(position);
                            if (resourceInfo != null) {
                                text1.setText(resourceInfo.getAnchor() + resourceInfo.getUri());
                            }
                            return view;
                        }
                    };
                    resourceListView.setAdapter(resourceArrayAdapter);
                    resourceListView.setOnItemClickListener(resourceItemClickListener);
                    discoverResourcesDialogBuilder.setView(resourceListView);

                    resourceArrayAdapter.setNotifyOnChange(false);
                    for (OcfResourceInfo resourceInfo : deviceInfo.getResourceInfos()) {
                        resourceArrayAdapter.add(resourceInfo);
                    }
                    resourceArrayAdapter.setNotifyOnChange(true);

                    resourceArrayAdapter.notifyDataSetChanged();

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
                    text1.setText(OCUuidUtil.uuidToString(deviceInfo.getUuid()));
                    text2.setText("\t" + deviceInfo.getName());
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
