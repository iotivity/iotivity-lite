package org.iotivity.onboardingtool;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import org.iotivity.OCClock;
import org.iotivity.OCMain;
import org.iotivity.OCObt;
import org.iotivity.OCObtDeviceStatusHandler;
import org.iotivity.OCObtDiscoveryHandler;
import org.iotivity.OCStorage;
import org.iotivity.OCUuidUtil;

import java.io.File;
import java.util.ArrayList;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class OnBoardingActivity extends AppCompatActivity {

    public final Lock lock = new ReentrantLock();
    public Condition cv = lock.newCondition();

    public static final long NANOS_PER_SECOND = 1000000000; // 1.e09

    private static final String TAG = OnBoardingActivity.class.getSimpleName();

    private RadioButton ownedRadioButton;
    private RadioButton unownedRadioButton;
    private Button refreshButton;
    private ListView listView;

    private OCObtDiscoveryHandler ownedDiscoveryHandler;
    private OCObtDiscoveryHandler unownedDiscoveryHandler;
    private OCObtDeviceStatusHandler justWorksHandler;

    private AdapterView.OnItemClickListener ownedItemClickListener;
    private AdapterView.OnItemClickListener unownedItemClickListener;

    private ArrayAdapter<String> ownedArrayAdapter;
    private ArrayAdapter<String> unownedArrayAdapter;

    private ArrayList<String> ownedDeviceList = new ArrayList<>();
    private ArrayList<String> unownedDeviceList = new ArrayList<>();

    private boolean quit;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ownedDiscoveryHandler = new OwnedDeviceHandler(this);
        unownedDiscoveryHandler = new UnownedDeviceHandler(this);
        justWorksHandler = new JustWorksHandler(this);

        unownedItemClickListener = new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final String uuid = unownedArrayAdapter.getItem((int) id);
                if (uuid != null) {
                    AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                    final View dialogView = LayoutInflater.from(OnBoardingActivity.this).inflate(R.layout.dialog_just_works, null);
                    alertDialogBuilder.setView(dialogView);

                    alertDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            new Thread(new Runnable() {
                                public void run() {
                                    if (OCObt.performJustWorksOtm(OCUuidUtil.stringToUuid(uuid), justWorksHandler) < 0) {
                                        final String msg = "Failed to perform ownership transfer for uuid " + uuid;
                                        Log.d(TAG, msg);
                                        runOnUiThread(new Runnable() {
                                            public void run() {
                                                Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                            }
                                        });
                                    }
                                }
                            }).start();
                        }
                    });

                    alertDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                        }
                    });

                    Dialog updateDialog = alertDialogBuilder.create();
                    ((TextView) dialogView.findViewById(R.id.uuid_text)).setText(uuid);

                    updateDialog.show();

                } else {
                    Log.w(TAG, "Uuid not found in list");
                }
            }
        };

        ownedRadioButton = (RadioButton) findViewById(R.id.owned_radio_button);
        ownedRadioButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ownedArrayAdapter.setNotifyOnChange(false);
                ownedArrayAdapter.clear();
                ownedArrayAdapter.setNotifyOnChange(true);
                listView.setAdapter(ownedArrayAdapter);
//                listView.setOnItemClickListener(ownedItemClickListener); // TODO...

                new Thread(new Runnable() {
                    public void run() {
                        if (OCObt.discoverOwnedDevices(ownedDiscoveryHandler) < 0) {
                            Log.e(TAG, "Failed to discover owned devices");
                            // TODO toast
                        }
                    }
                }).start();

                refreshButton.setEnabled(true);
            }
        });

        unownedRadioButton = (RadioButton) findViewById(R.id.unowned_radio_button);
        unownedRadioButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                unownedArrayAdapter.setNotifyOnChange(false);
                unownedArrayAdapter.clear();
                unownedArrayAdapter.setNotifyOnChange(true);
                listView.setAdapter(unownedArrayAdapter);
                listView.setOnItemClickListener(unownedItemClickListener);

                new Thread(new Runnable() {
                    public void run() {
                        if (OCObt.discoverUnownedDevices(unownedDiscoveryHandler) < 0) {
                            Log.e(TAG, "Failed to discover unowned devices");
                            // TODO toast
                        }
                    }
                }).start();

                refreshButton.setEnabled(true);
            }
        });

        refreshButton = (Button) findViewById(R.id.refresh_button);
        refreshButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (ownedRadioButton.isChecked()) {
                    ownedArrayAdapter.setNotifyOnChange(false);
                    ownedArrayAdapter.clear();
                    ownedArrayAdapter.setNotifyOnChange(true);

                    ownedRadioButton.callOnClick();

                } else if (unownedRadioButton.isChecked()) {
                    unownedArrayAdapter.setNotifyOnChange(false);
                    unownedArrayAdapter.clear();
                    unownedArrayAdapter.setNotifyOnChange(true);

                    unownedRadioButton.callOnClick();
                }
            }
        });

        listView = (ListView) findViewById(R.id.list_view);

        ownedArrayAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, ownedDeviceList);
        unownedArrayAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, unownedDeviceList);

        if (savedInstanceState == null) {
            // start first time only
            File credsDir = new File(getFilesDir(), "on_boarding_tool_creds");
            Log.i(TAG, "Credentials directory is " + credsDir.getAbsolutePath());
            if (!credsDir.exists()) {
                boolean mkDirResult = credsDir.mkdir();
                if (mkDirResult) {
                    Log.i(TAG, "Created credentials directory " + credsDir.getAbsolutePath());
                } else {
                    Log.e(TAG, "Failed to create credentials directory " + credsDir.getAbsolutePath());
                }
            }
            OCStorage.storageConfig(credsDir.getAbsolutePath());

            ObtInitHandler handler = new ObtInitHandler(this);
            int initReturn = OCMain.mainInit(handler);
            if (initReturn < 0) {
                Log.e(TAG, "Error in mainInit return code = " + initReturn);
                return;
            }

            new Thread(new Runnable() {
                public void run() {
                    eventLoop();
                }
            }).start();
        }
    }

    @Override
    protected void onDestroy() {
        quit = true;
        Log.d(TAG, "Calling main_shutdown.");
        OCMain.mainShutdown();
        super.onDestroy();
    }

    public void addOwnedDevice(String deviceId) {
        synchronized (ownedArrayAdapter) {
            ownedArrayAdapter.setNotifyOnChange(false);
            ownedArrayAdapter.add(deviceId);
            ownedArrayAdapter.setNotifyOnChange(true);
        }

        runOnUiThread(new Runnable() {
            public void run() {
                ownedArrayAdapter.notifyDataSetChanged();
            }
        });
    }

    public void addUnownedDevice(String deviceId) {
        synchronized (unownedArrayAdapter) {
            unownedArrayAdapter.setNotifyOnChange(false);
            unownedArrayAdapter.add(deviceId);
            unownedArrayAdapter.setNotifyOnChange(true);
        }

        runOnUiThread(new Runnable() {
            public void run() {
                unownedArrayAdapter.notifyDataSetChanged();
            }
        });
    }

    private void eventLoop() {
        while (!quit) {
            long nextEvent = OCMain.mainPoll();
            lock.lock();
            try {
                if (nextEvent == 0) {
                    cv.await();
                } else {
                    long now = OCClock.clockTime();
                    long timeToWait = (NANOS_PER_SECOND / OCClock.OC_CLOCK_SECOND) * (nextEvent - now);
                    cv.awaitNanos(timeToWait);
                }
            } catch (InterruptedException e) {
                Log.d(TAG, e.getMessage());
            } finally {
                lock.unlock();
            }
        }
    }
}
