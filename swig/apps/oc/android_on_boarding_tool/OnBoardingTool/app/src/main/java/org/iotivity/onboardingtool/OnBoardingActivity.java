package org.iotivity.onboardingtool;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcAnonSecurityAce;
import org.iotivity.oc.OcAuthSecurityAce;
import org.iotivity.oc.OcObt;
import org.iotivity.oc.OcPlatform;
import org.iotivity.oc.OcRoleSecurityAce;
import org.iotivity.oc.OcSecurityAce;
import org.iotivity.oc.OcSubjectSecurityAce;
import org.iotivity.oc.OcUtils;

import java.util.ArrayList;

public class OnBoardingActivity extends AppCompatActivity {

    private static final String TAG = OnBoardingActivity.class.getSimpleName();

    private boolean isRadioChecking;
    private RadioGroup allRadioGroup;
    private RadioGroup realmRadioGroup;
    private RadioGroup siteRadioGroup;
    private RadioButton ownedRadioButton;
    private RadioButton unownedRadioButton;
    private RadioButton ownedRealmRadioButton;
    private RadioButton unownedRealmRadioButton;
    private RadioButton ownedSiteRadioButton;
    private RadioButton unownedSiteRadioButton;
    private Button resetObtButton;
    private Button refreshButton;
    private ListView listView;

    private AdapterView.OnItemClickListener ownedItemClickListener;
    private AdapterView.OnItemClickListener unownedItemClickListener;

    private ArrayAdapter<OcfDeviceInfo> ownedArrayAdapter;
    private ArrayAdapter<OcfDeviceInfo> unownedArrayAdapter;

    ArrayList<OcfDeviceInfo> ownedDeviceList = new ArrayList<>();
    ArrayList<OcfDeviceInfo> unownedDeviceList = new ArrayList<>();

    private final Object arrayAdapterSync = new Object();

    OcObt obt;
    private OcPlatform obtPlatform;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ownedItemClickListener = new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final OcfDeviceInfo deviceInfo = ownedArrayAdapter.getItem((int) id);
                if (deviceInfo != null) {
                    final String uuid = OCUuidUtil.uuidToString(deviceInfo.getUuid());
                    AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                    alertDialogBuilder.setTitle(uuid);
                    alertDialogBuilder.setItems(R.array.ownedDeviceActions, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            switch (which) {
                                case 0: // Provision pair-wise credentials
                                    AlertDialog.Builder selectDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    selectDialogBuilder.setTitle(R.string.selectDevice);
                                    final String[] secondDeviceList = new String[ownedDeviceList.size()];
                                    for (int i = 0; i < secondDeviceList.length; ++i) {
                                        secondDeviceList[i] = OCUuidUtil.uuidToString(ownedDeviceList.get(i).getUuid());
                                    }
                                    selectDialogBuilder.setItems(secondDeviceList, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            final String uuidPair = secondDeviceList[which];
                                            Log.d(TAG, "Pairing " + uuid + " and " + uuidPair);
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    if (obt.provisionPairwiseCredentials(OCUuidUtil.stringToUuid(uuid), OCUuidUtil.stringToUuid(uuidPair), new ProvisionCredentialsHandler(OnBoardingActivity.this)) < 0) {
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
                                    final String[] aceSubjectList = new String[ownedDeviceList.size() + 3];
                                    aceSubjectList[0] = getString(R.string.aceAnonClear);
                                    aceSubjectList[1] = getString(R.string.aceAuthCrypt);
                                    aceSubjectList[2] = getString(R.string.aceRole);
                                    for (int i = 0; i < ownedDeviceList.size(); ++i) {
                                        aceSubjectList[i + 3] = OCUuidUtil.uuidToString(ownedArrayAdapter.getItem(i).getUuid());
                                    }
                                    aceDialogBuilder.setItems(aceSubjectList, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            final String subject = aceSubjectList[which];
                                            Log.d(TAG, "Ace subject = " + subject);
                                            final OcSecurityAce ace;
                                            if (which == 0) {
                                                ace = new OcAnonSecurityAce();
                                            } else if (which == 1) {
                                                ace = new OcAuthSecurityAce();
                                            } else if (which == 2) {
                                                ace = null;
                                                // ace is left null for now and handled below
                                            } else {
                                                ace = new OcSubjectSecurityAce(OCUuidUtil.stringToUuid(aceSubjectList[which]));
                                            }

                                            if (ace != null) {
                                                AcePropertiesHelper acePropertiesHelper = new AcePropertiesHelper(OnBoardingActivity.this, obt, uuid, new ProvisionAce2Handler(OnBoardingActivity.this));
                                                acePropertiesHelper.getProperties(ace); // calls provisionAce()

                                            } else if (which == 2) {
                                                // Need to get role and authority first in order to create the ace
                                                AlertDialog.Builder roleDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);

                                                LinearLayout layout = new LinearLayout(OnBoardingActivity.this);
                                                layout.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
                                                layout.setOrientation(LinearLayout.VERTICAL);

                                                final EditText input = new EditText(OnBoardingActivity.this);
                                                layout.addView(input);

                                                String title = getString(R.string.roleDialogTitle);
                                                roleDialogBuilder.setTitle(title);
                                                roleDialogBuilder.setMessage(R.string.roleDialogMessage);
                                                roleDialogBuilder.setView(layout);

                                                roleDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                                    @Override
                                                    public void onClick(DialogInterface dialog, int which) {
                                                        String role = input.getText().toString().trim();
                                                        if (!role.isEmpty()) {
                                                            if (role.length() > 63) {
                                                                role = role.substring(0, 63);
                                                            }

                                                            final String aceRole = role;

                                                            AlertDialog.Builder authorityAlertBuilder = new AlertDialog.Builder(OnBoardingActivity.this);

                                                            LinearLayout layout = new LinearLayout(OnBoardingActivity.this);
                                                            layout.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
                                                            layout.setOrientation(LinearLayout.VERTICAL);

                                                            final EditText input = new EditText(OnBoardingActivity.this);
                                                            layout.addView(input);

                                                            String title = getString(R.string.authorityDialogTitle);
                                                            authorityAlertBuilder.setTitle(title);
                                                            authorityAlertBuilder.setMessage(R.string.authorityDialogMessage);
                                                            authorityAlertBuilder.setView(layout);

                                                            authorityAlertBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                                                @Override
                                                                public void onClick(DialogInterface dialog, int which) {
                                                                    String authority = input.getText().toString().trim();
                                                                    if (!authority.isEmpty()) {
                                                                        if (authority.length() > 63) {
                                                                            authority = authority.substring(0, 63);
                                                                        }
                                                                    } else {
                                                                        authority = null;
                                                                    }
                                                                    final OcSecurityAce ace = new OcRoleSecurityAce(aceRole, authority);
                                                                    AcePropertiesHelper acePropertiesHelper = new AcePropertiesHelper(OnBoardingActivity.this, obt, uuid, new ProvisionAce2Handler(OnBoardingActivity.this));
                                                                    acePropertiesHelper.getProperties(ace); // calls provisionAce()
                                                                }
                                                            });

                                                            Dialog authorityDialog = authorityAlertBuilder.create();
                                                            authorityDialog.show();
                                                        }
                                                    }
                                                });

                                                Dialog roleDialog = roleDialogBuilder.create();
                                                roleDialog.show();

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

                                case 2: // Provision auth-crypt RW access to NCRs
                                    AlertDialog.Builder authCryptRwDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    authCryptRwDialogBuilder.setTitle(uuid);
                                    authCryptRwDialogBuilder.setMessage(getResources().getStringArray(R.array.ownedDeviceActions)[which]);

                                    authCryptRwDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    if (obt.provisionAuthWildcardAce(OCUuidUtil.stringToUuid(uuid), new ProvisionAuthWildcardAceHandler(OnBoardingActivity.this)) < 0) {
                                                        final String msg = "Failed to provision auth-crypt * ACE for uuid " + uuid;
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

                                    authCryptRwDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                        }
                                    });

                                    Dialog authCryptRwDialog = authCryptRwDialogBuilder.create();
                                    authCryptRwDialog.show();
                                    break;

                                case 3: // Provision role RW access to NCRs
                                    AlertDialog.Builder roleDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);

                                    LinearLayout layout = new LinearLayout(OnBoardingActivity.this);
                                    layout.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
                                    layout.setOrientation(LinearLayout.VERTICAL);

                                    final EditText input = new EditText(OnBoardingActivity.this);
                                    layout.addView(input);

                                    String title = getString(R.string.roleDialogTitle);
                                    roleDialogBuilder.setTitle(title);
                                    roleDialogBuilder.setMessage(R.string.roleDialogMessage);
                                    roleDialogBuilder.setView(layout);

                                    roleDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            String role = input.getText().toString().trim();
                                            if (!role.isEmpty()) {
                                                if (role.length() > 63) {
                                                    role = role.substring(0, 63);
                                                }

                                                final String aceRole = role;

                                                AlertDialog.Builder authorityAlertBuilder = new AlertDialog.Builder(OnBoardingActivity.this);

                                                LinearLayout layout = new LinearLayout(OnBoardingActivity.this);
                                                layout.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
                                                layout.setOrientation(LinearLayout.VERTICAL);

                                                final EditText input = new EditText(OnBoardingActivity.this);
                                                layout.addView(input);

                                                String title = getString(R.string.authorityDialogTitle);
                                                authorityAlertBuilder.setTitle(title);
                                                authorityAlertBuilder.setMessage(R.string.authorityDialogMessage);
                                                authorityAlertBuilder.setView(layout);

                                                authorityAlertBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                                    @Override
                                                    public void onClick(DialogInterface dialog, int which) {
                                                        String authority = input.getText().toString().trim();
                                                        if (!authority.isEmpty()) {
                                                            if (authority.length() > 63) {
                                                                authority = authority.substring(0, 63);
                                                            }
                                                        } else {
                                                            authority = null;
                                                        }

                                                        final String aceAuthority = authority;

                                                        new Thread(new Runnable() {
                                                            public void run() {
                                                                if (obt.provisionRoleWildcardAce(OCUuidUtil.stringToUuid(uuid), aceRole, aceAuthority, new ProvisionRoleWildcardAceHandler(OnBoardingActivity.this)) < 0) {
                                                                    final String msg = "Failed to provision role * ACE for uuid " + uuid;
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

                                                Dialog authorityDialog = authorityAlertBuilder.create();
                                                authorityDialog.show();
                                            }
                                        }
                                    });

                                    Dialog roleDialog = roleDialogBuilder.create();
                                    roleDialog.show();
                                    break;

                                case 4: // Provision identity certificate
                                    AlertDialog.Builder idCertDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    idCertDialogBuilder.setTitle(uuid);
                                    idCertDialogBuilder.setMessage(getResources().getStringArray(R.array.ownedDeviceActions)[which]);

                                    idCertDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    if (obt.provisionIdentityCertificate(OCUuidUtil.stringToUuid(uuid), new ProvisionIdCertificateHandler(OnBoardingActivity.this)) < 0) {
                                                        final String msg = "Failed to provision identity certificate for uuid " + uuid;
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

                                    idCertDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                        }
                                    });

                                    Dialog idCertDialog = idCertDialogBuilder.create();
                                    idCertDialog.show();
                                    break;

                                case 5: // Provision role certificate
                                    RoleCertificateHelper roleCertificateHelper = new RoleCertificateHelper(OnBoardingActivity.this, obt, uuid, new ProvisionRoleCertificateHandler(OnBoardingActivity.this));
                                    roleCertificateHelper.getRoles(null); // calls provisionRoleCertificate()
                                    break;

                                case 6: // Reset Device
                                    AlertDialog.Builder resetDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    resetDialogBuilder.setTitle(uuid);
                                    resetDialogBuilder.setMessage(getResources().getStringArray(R.array.ownedDeviceActions)[which]);

                                    resetDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    if (obt.deviceHardReset(OCUuidUtil.stringToUuid(uuid), new DeviceResetHandler(OnBoardingActivity.this)) < 0) {
                                                        final String msg = "Failed to perform device reset for uuid " + uuid;
                                                        Log.d(TAG, msg);
                                                        runOnUiThread(new Runnable() {
                                                            public void run() {
                                                                Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                                            }
                                                        });
                                                    } else {
                                                        removeOwnedDevice(deviceInfo);
                                                    }
                                                }
                                            }).start();
                                        }
                                    });

                                    resetDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                        }
                                    });

                                    Dialog resetDeviceDialog = resetDialogBuilder.create();
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
                final OcfDeviceInfo deviceInfo = unownedArrayAdapter.getItem((int) id);
                if (deviceInfo != null) {
                    final String uuid = OCUuidUtil.uuidToString(deviceInfo.getUuid());
                    AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                    alertDialogBuilder.setTitle(uuid);
                    alertDialogBuilder.setItems(R.array.unownedDeviceActions, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            switch (which) {
                                case 0: // Just Works OTM
                                    AlertDialog.Builder justWorksOtmDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    justWorksOtmDialogBuilder.setTitle(uuid);
                                    justWorksOtmDialogBuilder.setMessage(getResources().getStringArray(R.array.unownedDeviceActions)[0]);

                                    justWorksOtmDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    if (obt.performJustWorksOtm(OCUuidUtil.stringToUuid(uuid), new JustWorksHandler(OnBoardingActivity.this)) < 0) {
                                                        final String msg = "Failed to perform ownership transfer for uuid " + uuid;
                                                        Log.d(TAG, msg);
                                                        runOnUiThread(new Runnable() {
                                                            public void run() {
                                                                Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                                            }
                                                        });
                                                    } else {
                                                        removeUnownedDevice(deviceInfo);
                                                    }
                                                }
                                            }).start();
                                        }
                                    });

                                    justWorksOtmDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                        }
                                    });

                                    Dialog justWorksOtmDialog = justWorksOtmDialogBuilder.create();
                                    justWorksOtmDialog.show();
                                    break;

                                case 1: // Generate Random Pin
                                    AlertDialog.Builder generateRandomPinDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    generateRandomPinDialogBuilder.setTitle(uuid);
                                    generateRandomPinDialogBuilder.setMessage(getResources().getStringArray(R.array.unownedDeviceActions)[1]);

                                    generateRandomPinDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    if (obt.requestRandomPin(OCUuidUtil.stringToUuid(uuid), new GenerateRandomPinHandler(OnBoardingActivity.this)) < 0) {
                                                        final String msg = "Failed to generate random pin for uuid " + uuid;
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

                                    generateRandomPinDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                        }
                                    });

                                    Dialog generateRandomPinDialog = generateRandomPinDialogBuilder.create();
                                    generateRandomPinDialog.show();
                                    break;

                                case 2: // Random Pin OTM
                                    LinearLayout layout = new LinearLayout(OnBoardingActivity.this);
                                    layout.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
                                    layout.setOrientation(LinearLayout.VERTICAL);

                                    final EditText input = new EditText(OnBoardingActivity.this);
                                    layout.addView(input);

                                    AlertDialog.Builder randomPinOtmDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    randomPinOtmDialogBuilder.setTitle(uuid);
                                    randomPinOtmDialogBuilder.setMessage(R.string.enterPin);
                                    randomPinOtmDialogBuilder.setView(layout);

                                    randomPinOtmDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    String pin = input.getText().toString().trim();
                                                    if (pin.length() > 24) {
                                                        pin = pin.substring(0, 24);
                                                    }
                                                    Log.d(TAG, "PIN = " + pin);
                                                    if (obt.performRandomPinOtm(OCUuidUtil.stringToUuid(uuid), pin, new OtmRandomPinHandler(OnBoardingActivity.this)) < 0) {
                                                        final String msg = "Failed to perform ownership transfer for uuid " + uuid;
                                                        Log.d(TAG, msg);
                                                        runOnUiThread(new Runnable() {
                                                            public void run() {
                                                                Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                                            }
                                                        });
                                                    } else {
                                                        removeUnownedDevice(deviceInfo);
                                                    }
                                                }
                                            }).start();
                                        }
                                    });

                                    randomPinOtmDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                        }
                                    });

                                    Dialog randomPinOtmDialog = randomPinOtmDialogBuilder.create();
                                    randomPinOtmDialog.show();
                                    break;

                                case 3: // Manufacturer Certificate OTM
                                    AlertDialog.Builder mfgCertOtmDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                                    mfgCertOtmDialogBuilder.setTitle(uuid);
                                    mfgCertOtmDialogBuilder.setMessage(getResources().getStringArray(R.array.unownedDeviceActions)[3]);

                                    mfgCertOtmDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            new Thread(new Runnable() {
                                                public void run() {
                                                    if (obt.performCertOtm(OCUuidUtil.stringToUuid(uuid), new OtmCertificationHandler(OnBoardingActivity.this)) < 0) {
                                                        final String msg = "Failed to perform ownership transfer for uuid " + uuid;
                                                        Log.d(TAG, msg);
                                                        runOnUiThread(new Runnable() {
                                                            public void run() {
                                                                Toast.makeText(OnBoardingActivity.this, msg, Toast.LENGTH_LONG).show();
                                                            }
                                                        });
                                                    } else {
                                                        removeUnownedDevice(deviceInfo);
                                                    }
                                                }
                                            }).start();
                                        }
                                    });

                                    mfgCertOtmDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                        }
                                    });

                                    Dialog mfgCertOtmDialog = mfgCertOtmDialogBuilder.create();
                                    mfgCertOtmDialog.show();
                                    break;

                                default:
                                    break;
                            }
                        }
                    });

                    Dialog unownedDeviceDialog = alertDialogBuilder.create();
                    unownedDeviceDialog.show();

                } else {
                    Log.w(TAG, "Uuid not found in list");
                }
            }
        };

        allRadioGroup = (RadioGroup) findViewById(R.id.radio_group);
        realmRadioGroup = (RadioGroup) findViewById(R.id.realm_radio_group);
        siteRadioGroup = (RadioGroup) findViewById(R.id.site_radio_group);

        allRadioGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                if ((checkedId != -1) && isRadioChecking) {
                    isRadioChecking = false;
                    realmRadioGroup.clearCheck();
                    siteRadioGroup.clearCheck();
                }
                isRadioChecking = true;
            }
        });

        realmRadioGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                if ((checkedId != -1) && isRadioChecking) {
                    isRadioChecking = false;
                    allRadioGroup.clearCheck();
                    siteRadioGroup.clearCheck();
                }
                isRadioChecking = true;
            }
        });

        siteRadioGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                if ((checkedId != -1) && isRadioChecking) {
                    isRadioChecking = false;
                    allRadioGroup.clearCheck();
                    realmRadioGroup.clearCheck();
                }
                isRadioChecking = true;
            }
        });

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
                        if (obt.discoverOwnedDevices(new OwnedDeviceHandler(OnBoardingActivity.this)) < 0) {
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

        ownedRealmRadioButton = (RadioButton) findViewById(R.id.owned_realm_radio_button);
        ownedRealmRadioButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ownedArrayAdapter.setNotifyOnChange(false);
                ownedArrayAdapter.clear();
                ownedArrayAdapter.setNotifyOnChange(true);
                listView.setAdapter(ownedArrayAdapter);
                listView.setOnItemClickListener(ownedItemClickListener);

                new Thread(new Runnable() {
                    public void run() {
                        if (obt.discoverOwnedDevicesRealmLocalIPv6(new OwnedDeviceHandler(OnBoardingActivity.this)) < 0) {
                            final String msg = "Failed to discover owned realm local devices";
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

        ownedSiteRadioButton = (RadioButton) findViewById(R.id.owned_site_radio_button);
        ownedSiteRadioButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ownedArrayAdapter.setNotifyOnChange(false);
                ownedArrayAdapter.clear();
                ownedArrayAdapter.setNotifyOnChange(true);
                listView.setAdapter(ownedArrayAdapter);
                listView.setOnItemClickListener(ownedItemClickListener);

                new Thread(new Runnable() {
                    public void run() {
                        if (obt.discoverOwnedDevicesSiteLocalIPv6(new OwnedDeviceHandler(OnBoardingActivity.this)) < 0) {
                            final String msg = "Failed to discover owned site local devices";
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
                        if (obt.discoverUnownedDevices(new UnownedDeviceHandler(OnBoardingActivity.this)) < 0) {
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

        unownedRealmRadioButton = (RadioButton) findViewById(R.id.unowned_realm_radio_button);
        unownedRealmRadioButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                unownedArrayAdapter.setNotifyOnChange(false);
                unownedArrayAdapter.clear();
                unownedArrayAdapter.setNotifyOnChange(true);
                listView.setAdapter(unownedArrayAdapter);
                listView.setOnItemClickListener(unownedItemClickListener);

                new Thread(new Runnable() {
                    public void run() {
                        if (obt.discoverUnownedDevicesRealmLocalIPv6(new UnownedDeviceHandler(OnBoardingActivity.this)) < 0) {
                            final String msg = "Failed to discover unowned realm local devices";
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

        unownedSiteRadioButton = (RadioButton) findViewById(R.id.unowned_site_radio_button);
        unownedSiteRadioButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                unownedArrayAdapter.setNotifyOnChange(false);
                unownedArrayAdapter.clear();
                unownedArrayAdapter.setNotifyOnChange(true);
                listView.setAdapter(unownedArrayAdapter);
                listView.setOnItemClickListener(unownedItemClickListener);

                new Thread(new Runnable() {
                    public void run() {
                        if (obt.discoverUnownedDevicesSiteLocalIPv6(new UnownedDeviceHandler(OnBoardingActivity.this)) < 0) {
                            final String msg = "Failed to discover unowned site local devices";
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

                } else if (ownedRealmRadioButton.isChecked()) {
                    ownedArrayAdapter.setNotifyOnChange(false);
                    ownedArrayAdapter.clear();
                    ownedArrayAdapter.setNotifyOnChange(true);

                    ownedRealmRadioButton.callOnClick();

                } else if (ownedSiteRadioButton.isChecked()) {
                    ownedArrayAdapter.setNotifyOnChange(false);
                    ownedArrayAdapter.clear();
                    ownedArrayAdapter.setNotifyOnChange(true);

                    ownedSiteRadioButton.callOnClick();

                } else if (unownedRadioButton.isChecked()) {
                    unownedArrayAdapter.setNotifyOnChange(false);
                    unownedArrayAdapter.clear();
                    unownedArrayAdapter.setNotifyOnChange(true);

                    unownedRadioButton.callOnClick();

                } else if (unownedRealmRadioButton.isChecked()) {
                    unownedArrayAdapter.setNotifyOnChange(false);
                    unownedArrayAdapter.clear();
                    unownedArrayAdapter.setNotifyOnChange(true);

                    unownedRealmRadioButton.callOnClick();

                } else if (unownedSiteRadioButton.isChecked()) {
                    unownedArrayAdapter.setNotifyOnChange(false);
                    unownedArrayAdapter.clear();
                    unownedArrayAdapter.setNotifyOnChange(true);

                    unownedSiteRadioButton.callOnClick();
                }
            }
        });

        resetObtButton = (Button) findViewById(R.id.reset_obt);
        resetObtButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                AlertDialog.Builder resetObtDialogBuilder = new AlertDialog.Builder(OnBoardingActivity.this);
                resetObtDialogBuilder.setTitle(getString(R.string.resetObt));
                resetObtDialogBuilder.setMessage(getString(R.string.resetMessage));

                resetObtDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        obtPlatform.reset();
                        obt.shutdown();
                        ownedDeviceList.clear();
                        ownedArrayAdapter.notifyDataSetChanged();
                        unownedDeviceList.clear();
                        unownedArrayAdapter.notifyDataSetChanged();
                        obt = new OcObt();
                    }
                });

                resetObtDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                    }
                });

                Dialog resetObtDialog = resetObtDialogBuilder.create();
                resetObtDialog.show();
            }
        });

        listView = (ListView) findViewById(R.id.list_view);

        ownedArrayAdapter = new ArrayAdapter(this, android.R.layout.simple_list_item_2, android.R.id.text1, ownedDeviceList) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                View view = super.getView(position, convertView, parent);
                TextView text1 = (TextView) view.findViewById(android.R.id.text1);
                TextView text2 = (TextView) view.findViewById(android.R.id.text2);

                OcfDeviceInfo deviceInfo = ownedArrayAdapter.getItem(position);
                if (deviceInfo != null) {
                    text1.setText(OCUuidUtil.uuidToString(ownedDeviceList.get(position).getUuid()));
                    text2.setText("\t" + ownedDeviceList.get(position).getName());
                }
                return view;
            }
        };
        unownedArrayAdapter = new ArrayAdapter(this, android.R.layout.simple_list_item_2, android.R.id.text1, unownedDeviceList) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                View view = super.getView(position, convertView, parent);
                TextView text1 = (TextView) view.findViewById(android.R.id.text1);
                TextView text2 = (TextView) view.findViewById(android.R.id.text2);

                OcfDeviceInfo deviceInfo = unownedArrayAdapter.getItem(position);
                if (deviceInfo != null) {
                    text1.setText(OCUuidUtil.uuidToString(unownedDeviceList.get(position).getUuid()));
                    text2.setText("\t" + unownedDeviceList.get(position).getName());
                }
                return view;
            }
        };

        if (savedInstanceState == null) {
            // start first time only

            // Note: If using a factory presets handler,
            // the factory presets handler must be set prior to calling
            // systemInit().
            // The systemInit() function will cause the factory presets handler to
            // be called if it is set.
            OcUtils.setFactoryPresetsHandler(new FactoryPresetsHandler(this));

            obtPlatform = OcPlatform.getInstance();
            ObtInitHandler handler = new ObtInitHandler(this, obtPlatform);
            obtPlatform.systemInit(handler);
            obt = new OcObt();
        }
    }

    @Override
    protected void onDestroy() {
        Log.d(TAG, "Calling Shutdown.");
        obtPlatform.systemShutdown();
        obt.shutdown();
        super.onDestroy();
    }

    public void addOwnedDevice(OcfDeviceInfo deviceInfo) {
        synchronized (arrayAdapterSync) {
            ownedArrayAdapter.setNotifyOnChange(false);
            ownedArrayAdapter.add(deviceInfo);
            ownedArrayAdapter.setNotifyOnChange(true);
        }

        runOnUiThread(new Runnable() {
            public void run() {
                ownedArrayAdapter.notifyDataSetChanged();
            }
        });
    }

    public void addUnownedDevice(OcfDeviceInfo deviceInfo) {
        synchronized (arrayAdapterSync) {
            unownedArrayAdapter.setNotifyOnChange(false);
            unownedArrayAdapter.add(deviceInfo);
            unownedArrayAdapter.setNotifyOnChange(true);
        }

        runOnUiThread(new Runnable() {
            public void run() {
                unownedArrayAdapter.notifyDataSetChanged();
            }
        });
    }

    public void removeOwnedDevice(OcfDeviceInfo deviceInfo) {
        synchronized (arrayAdapterSync) {
            ownedArrayAdapter.setNotifyOnChange(false);
            ownedArrayAdapter.remove(deviceInfo);
            ownedArrayAdapter.setNotifyOnChange(true);
        }

        runOnUiThread(new Runnable() {
            public void run() {
                ownedArrayAdapter.notifyDataSetChanged();
            }
        });
    }

    public void removeUnownedDevice(OcfDeviceInfo deviceInfo) {
        synchronized (arrayAdapterSync) {
            unownedArrayAdapter.setNotifyOnChange(false);
            unownedArrayAdapter.remove(deviceInfo);
            unownedArrayAdapter.setNotifyOnChange(true);
        }

        runOnUiThread(new Runnable() {
            public void run() {
                unownedArrayAdapter.notifyDataSetChanged();
            }
        });
    }
}
