package org.iotivity.onboardingtool;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.RadioButton;
import android.widget.Toast;

import org.iotivity.OCAceConnectionType;
import org.iotivity.OCMain;
import org.iotivity.OCObt;
import org.iotivity.OCSecurityAce;
import org.iotivity.OCUuidUtil;

import java.util.ArrayList;

public class OnBoardingActivity extends AppCompatActivity {

    private static final String TAG = OnBoardingActivity.class.getSimpleName();

    private RadioButton ownedRadioButton;
    private RadioButton unownedRadioButton;
    private Button refreshButton;
    private ListView listView;

    private AdapterView.OnItemClickListener ownedItemClickListener;
    private AdapterView.OnItemClickListener unownedItemClickListener;

    private ArrayAdapter<String> ownedArrayAdapter;
    private ArrayAdapter<String> unownedArrayAdapter;

    private ArrayList<String> ownedDeviceList = new ArrayList<>();
    private ArrayList<String> unownedDeviceList = new ArrayList<>();

    private final Object arrayAdapterSync = new Object();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ownedItemClickListener = new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final String uuid = ownedArrayAdapter.getItem((int) id);
                if (uuid != null) {
                    AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                    alertDialogBuilder.setTitle(uuid);
                    alertDialogBuilder.setItems(R.array.ownedDeviceActions, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            switch (which) {
                                case 0: // Provision pair-wise credentials
                                    AlertDialog.Builder selectDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    selectDialogBuilder.setTitle(R.string.selectDevice);
                                    String[] secondDeviceList = ownedDeviceList.toArray(new String[ownedDeviceList.size()]);
                                    selectDialogBuilder.setItems(secondDeviceList, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            final String uuidPair = ownedDeviceList.get(which);
                                            Log.d(TAG, "Pairing " + uuid + " and " + uuidPair);
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    if (OCObt.provisionPairwiseCredentials(OCUuidUtil.stringToUuid(uuid), OCUuidUtil.stringToUuid(uuidPair), new ProvisionCredentialsHandler(OnBoardingActivity.this)) < 0) {
                                                        final String msg = "Failed to provision credentials for " + uuid + " and " + uuidPair;
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

                                    Dialog provisionPairDialog = selectDialogBuilder.create();
                                    provisionPairDialog.show();
                                    break;

                                case 1: // Provision ACE2
                                    AlertDialog.Builder aceDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    aceDialogBuilder.setTitle(R.string.selectAceSubject);
                                    final String[] aceSubjectList = new String[ownedDeviceList.size() + 2];
                                    aceSubjectList[0] = getResources().getString(R.string.aceAnonClear);
                                    aceSubjectList[1] = getResources().getString(R.string.aceAuthCrypt);
                                    for (int i = 0; i < ownedDeviceList.size(); ++i) {
                                        aceSubjectList[i + 2] = ownedDeviceList.get(i);
                                    }
                                    aceDialogBuilder.setItems(aceSubjectList, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            final String subject = aceSubjectList[which];
                                            Log.d(TAG, "Ace subject = " + subject);
                                            final OCSecurityAce ace;
                                            if (which == 0) {
                                                ace = OCObt.newAceForConnection(OCAceConnectionType.OC_CONN_ANON_CLEAR);
                                            } else if (which == 1) {
                                                ace = OCObt.newAceForConnection(OCAceConnectionType.OC_CONN_AUTH_CRYPT);
                                            } else {
                                                ace = OCObt.newAceForSubject(OCUuidUtil.stringToUuid(aceSubjectList[which]));
                                            }

                                            if (ace != null) {
                                                AcePropertiesHelper acePropertiesHelper = new AcePropertiesHelper(OnBoardingActivity.this, uuid, new ProvisionAce2Handler(OnBoardingActivity.this));
                                                acePropertiesHelper.getProperties(ace); // calls provisionAce()
                                            } else {
                                                final String msg = "Failed to create ace object for device " + uuid;
                                                Log.d(TAG, msg);
                                                runOnUiThread(new Runnable() {
                                                    public void run() {
                                                        Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                                    }
                                                });
                                            }
                                        }
                                    });

                                    Dialog provisionAceDialog = aceDialogBuilder.create();
                                    provisionAceDialog.show();
                                    break;

                                case 2: // Reset Device
                                    AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    alertDialogBuilder.setTitle(uuid);
                                    alertDialogBuilder.setMessage(getResources().getStringArray(R.array.ownedDeviceActions)[2]);

                                    alertDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    if (OCObt.deviceHardReset(OCUuidUtil.stringToUuid(uuid), new DeviceResetHandler(OnBoardingActivity.this)) < 0) {
                                                        final String msg = "Failed to perform device reset for uuid " + uuid;
                                                        Log.d(TAG, msg);
                                                        runOnUiThread(new Runnable() {
                                                            public void run() {
                                                                Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                                            }
                                                        });
                                                    } else {
                                                        removeOwnedDevice(uuid);
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

                                    Dialog resetDeviceDialog = alertDialogBuilder.create();
                                    resetDeviceDialog.show();
                                    break;

                                default:
                                    break;
                            }
                        }
                    });

                    Dialog ownedDeviceDialog = alertDialogBuilder.create();
                    ownedDeviceDialog.show();

                } else {
                    Log.w(TAG, "Uuid not found in list");
                }
            }
        };

        unownedItemClickListener = new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final String uuid = unownedArrayAdapter.getItem((int) id);
                if (uuid != null) {
                    AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                    alertDialogBuilder.setTitle(uuid);
                    alertDialogBuilder.setMessage(R.string.justWorks);

                    alertDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            new Thread(new Runnable() {
                                public void run() {
                                    if (OCObt.performJustWorksOtm(OCUuidUtil.stringToUuid(uuid), new JustWorksHandler(OnBoardingActivity.this)) < 0) {
                                        final String msg = "Failed to perform ownership transfer for uuid " + uuid;
                                        Log.d(TAG, msg);
                                        runOnUiThread(new Runnable() {
                                            public void run() {
                                                Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                            }
                                        });
                                    } else {
                                        removeUnownedDevice(uuid);
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

                    Dialog justWorksDialog = alertDialogBuilder.create();
                    justWorksDialog.show();

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
                listView.setOnItemClickListener(ownedItemClickListener);

                new Thread(new Runnable() {
                    public void run() {
                        if (OCObt.discoverOwnedDevices(new OwnedDeviceHandler(OnBoardingActivity.this)) < 0) {
                            final String msg = "Failed to discover owned devices";
                            Log.d(TAG, msg);
                            runOnUiThread(new Runnable() {
                                public void run() {
                                    Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                }
                            });
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
                        if (OCObt.discoverUnownedDevices(new UnownedDeviceHandler(OnBoardingActivity.this)) < 0) {
                            final String msg = "Failed to discover unowned devices";
                            Log.d(TAG, msg);
                            runOnUiThread(new Runnable() {
                                public void run() {
                                    Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                }
                            });
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
            ObtInitHandler handler = new ObtInitHandler(this);
            int initReturn = OCMain.mainInit(handler);
            if (initReturn < 0) {
                Log.e(TAG, "Error in mainInit return code = " + initReturn);
                return;
            }
        }
    }

    @Override
    protected void onDestroy() {
        Log.d(TAG, "Calling main_shutdown.");
        OCMain.mainShutdown();
        super.onDestroy();
    }

    public void addOwnedDevice(String deviceId) {
        synchronized (arrayAdapterSync) {
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
        synchronized (arrayAdapterSync) {
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

    public void removeOwnedDevice(String deviceId) {
        synchronized (arrayAdapterSync) {
            ownedArrayAdapter.setNotifyOnChange(false);
            ownedArrayAdapter.remove(deviceId);
            ownedArrayAdapter.setNotifyOnChange(true);
        }

        runOnUiThread(new Runnable() {
            public void run() {
                ownedArrayAdapter.notifyDataSetChanged();
            }
        });
    }

    public void removeUnownedDevice(String deviceId) {
        synchronized (arrayAdapterSync) {
            unownedArrayAdapter.setNotifyOnChange(false);
            unownedArrayAdapter.remove(deviceId);
            unownedArrayAdapter.setNotifyOnChange(true);
        }

        runOnUiThread(new Runnable() {
            public void run() {
                unownedArrayAdapter.notifyDataSetChanged();
            }
        });
    }
}
