package com.deepdatago.provider;

import android.content.ContentProvider;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.UriMatcher;

import android.database.Cursor;
import android.database.SQLException;

import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteQueryBuilder;

import android.net.Uri;
import android.text.TextUtils;

import java.util.HashMap;
import com.deepdatago.account.*;

/**
 * Created by tnnd on 7/15/18.
 */

public class CryptoProvider extends ContentProvider {
    private static HashMap<String, String> STUDENTS_PROJECTION_MAP;

    static final int ACCOUNT = 1;
    static final int FRIEND = 2;
    static final int GROUPS = 3;

    /**
     * Database specific constant declarations
     */

    private SQLiteDatabase db;
    static final int DATABASE_VERSION = 4;

    static final UriMatcher uriMatcher;
    static{
        uriMatcher = new UriMatcher(UriMatcher.NO_MATCH);
        uriMatcher.addURI(Tags.PROVIDER_NAME, "/" + Tags.ACCOUNT_TABLE_NAME, ACCOUNT);
        uriMatcher.addURI(Tags.PROVIDER_NAME, "/" + Tags.FRIENDS_KEYS_TABLE_NAME, FRIEND);
        uriMatcher.addURI(Tags.PROVIDER_NAME, "/" + Tags.GROUPS_KEYS_TABLE_NAME, GROUPS);
    }

    static final String CREATE_FRIENDS_KEYS_TABLE =
            " CREATE TABLE " + Tags.FRIENDS_KEYS_TABLE_NAME +
                    " (" + Tags.DB_FIELD_PRIMARY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    Tags.DB_FIELD_ACCOUNT + " TEXT UNIQUE NOT NULL, " +
                    Tags.DB_FIELD_PRIVATE_SYMMETRIC_KEY + " TEXT NOT NULL, " +
                    Tags.DB_FIELD_SHARED_SYMMETRIC_KEY + " TEXT NOT NULL);";

    static final String CREATE_DB_TABLE =
            " CREATE TABLE " + Tags.ACCOUNT_TABLE_NAME +
                    " (" + Tags.DB_FIELD_PRIMARY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    Tags.DB_FIELD_SHARED_SYMMETRIC_KEY + " TEXT NOT NULL, " +
                    Tags.DB_FIELD_XMPP_USER_NAME + " TEXT, " +
                    Tags.DB_FIELD_PASSOWRD + " TEXT, " +
                    Tags.DB_FIELD_XMPP_PASSOWRD + " TEXT);";

    static final String CREATE_GROUPSS_KEYS_TABLE =
            " CREATE TABLE " + Tags.GROUPS_KEYS_TABLE_NAME +
                    " (" + Tags.DB_FIELD_PRIMARY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    Tags.DB_FIELD_GROUP_ADDRESS + " TEXT UNIQUE NOT NULL, " +
                    Tags.DB_FIELD_GROUP_SYMMETRIC_KEY + " TEXT NOT NULL);";

    private static final String[] ACCOUNT_PROJECTION = {Tags.DB_FIELD_PRIMARY_ID, Tags.DB_FIELD_SHARED_SYMMETRIC_KEY};
    /**
     * Helper class that actually creates and manages
     * the provider's underlying data repository.
     */

    private static class DatabaseHelper extends SQLiteOpenHelper {
        DatabaseHelper(Context context){
            super(context, Tags.DATABASE_NAME, null, DATABASE_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(CREATE_DB_TABLE);
            db.execSQL(CREATE_FRIENDS_KEYS_TABLE);
            db.execSQL(CREATE_GROUPSS_KEYS_TABLE);
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            // db.execSQL("DROP TABLE IF EXISTS " +  FRIENDS_KEYS_TABLE_NAME);
            // db.execSQL(CREATE_FRIENDS_KEYS_TABLE);
            /*
            db.execSQL("DROP TABLE IF EXISTS " +  ACCOUNT_TABLE_NAME);
            db.execSQL("DROP TABLE IF EXISTS " +  FRIENDS_KEYS_TABLE_NAME);
            onCreate(db);
            */
        }
    }

    @Override
    public boolean onCreate() {
        Context context = getContext();
        DatabaseHelper dbHelper = new DatabaseHelper(context);

        /**
         * Create a write able database which will trigger its
         * creation if it doesn't already exist.
         */

        db = dbHelper.getWritableDatabase();
        return (db == null)? false:true;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        int UriTableType = uriMatcher.match(uri);
        switch (UriTableType) {
            case ACCOUNT:
                return insertAccountTable(uri, values);
            case FRIEND:
                return insertFriendTable(uri, values);
            case GROUPS:
                return insertGroupsTable(uri, values);
            default:
        }
        throw new SQLException("Failed to add a record into " + uri);
    }

    private Uri insertAccountTable(Uri uri, ContentValues values) {
        // account table should only have 1 record
        Cursor c = query(uri,	ACCOUNT_PROJECTION,	null,null, null);
        int cursorCount = c.getCount();

        final String URL = "content://" + Tags.PROVIDER_NAME + "/" + Tags.ACCOUNT_TABLE_NAME;
        final Uri CONTENT_URI = Uri.parse(URL);

        if (cursorCount > 0)
        {
            // delete(uri,	"_id>1",null);
            // update only
            String selection = Tags.DB_FIELD_PRIMARY_ID + "=1";
            int updateCount = update(uri, values, selection, null);
            int index = c.getColumnIndex(Tags.DB_FIELD_PRIMARY_ID);
            c.moveToFirst();
            long rowID = c.getLong(index);
            Uri _uri = ContentUris.withAppendedId(CONTENT_URI, rowID);
            getContext().getContentResolver().notifyChange(_uri, null);
            return _uri;
        }

        long rowID = db.insert(	Tags.ACCOUNT_TABLE_NAME, "", values);

        /**
         * If record is added successfully
         */
        if (rowID > 0) {
            Uri _uri = ContentUris.withAppendedId(CONTENT_URI, rowID);
            getContext().getContentResolver().notifyChange(_uri, null);
            return _uri;
        }

        throw new SQLException("Failed to add a record into " + uri);
    }

    private Uri insertFriendTable(Uri uri, ContentValues values) {
        // account table should only have 1 record
        final String[] projection = { Tags.DB_FIELD_ACCOUNT };

        String account = values.get(Tags.DB_FIELD_ACCOUNT).toString().replace("0x", "");

        String selection = Tags.DB_FIELD_ACCOUNT + "='" + account+"'";

        Cursor c = query(uri,	projection,	selection,null, null);
        int cursorCount = c.getCount();

        final String URL = "content://" + Tags.PROVIDER_NAME + "/" + Tags.FRIENDS_KEYS_TABLE_NAME;
        final Uri CONTENT_URI = Uri.parse(URL);

        if (cursorCount > 0)
        {
            // update only
            int updateCount = update(uri, values, selection, null);
            int index = c.getColumnIndex(Tags.DB_FIELD_PRIMARY_ID);
            c.moveToFirst();
            long rowID = c.getLong(index);
            Uri _uri = ContentUris.withAppendedId(CONTENT_URI, rowID);
            getContext().getContentResolver().notifyChange(_uri, null);
            return _uri;
        }

        long rowID = db.insert(	Tags.FRIENDS_KEYS_TABLE_NAME, "", values);

        /**
         * If record is added successfully
         */
        if (rowID > 0) {
            Uri _uri = ContentUris.withAppendedId(CONTENT_URI, rowID);
            getContext().getContentResolver().notifyChange(_uri, null);
            return _uri;
        }

        throw new SQLException("Failed to add a record into " + uri);
    }

    private Uri insertGroupsTable(Uri uri, ContentValues values) {
        // account table should only have 1 record
        final String[] projection = { Tags.DB_FIELD_GROUP_ADDRESS };

        String group = values.get(Tags.DB_FIELD_GROUP_ADDRESS).toString();

        String selection = Tags.DB_FIELD_GROUP_ADDRESS + "='" + group+"'";

        Cursor c = query(uri,	projection,	selection,null, null);
        int cursorCount = c.getCount();

        final String URL = "content://" + Tags.PROVIDER_NAME + "/" + Tags.GROUPS_KEYS_TABLE_NAME;
        final Uri CONTENT_URI = Uri.parse(URL);

        if (cursorCount > 0)
        {
            // update only
            int updateCount = update(uri, values, selection, null);
            int index = c.getColumnIndex(Tags.DB_FIELD_PRIMARY_ID);
            c.moveToFirst();
            long rowID = c.getLong(index);
            Uri _uri = ContentUris.withAppendedId(CONTENT_URI, rowID);
            getContext().getContentResolver().notifyChange(_uri, null);
            return _uri;
        }

        long rowID = db.insert(	Tags.GROUPS_KEYS_TABLE_NAME, "", values);

        /**
         * If record is added successfully
         */
        if (rowID > 0) {
            Uri _uri = ContentUris.withAppendedId(CONTENT_URI, rowID);
            getContext().getContentResolver().notifyChange(_uri, null);
            return _uri;
        }

        throw new SQLException("Failed to add a record into " + uri);
    }

    @Override
    public Cursor query(Uri uri, String[] projection,
                        String selection,String[] selectionArgs, String sortOrder) {
        SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
        int UriTableType = uriMatcher.match(uri);
        switch (UriTableType) {
            case ACCOUNT:
                qb.setTables(Tags.ACCOUNT_TABLE_NAME);
                break;
            case FRIEND:
                qb.setTables(Tags.FRIENDS_KEYS_TABLE_NAME);
                break;
            case GROUPS:
                qb.setTables(Tags.GROUPS_KEYS_TABLE_NAME);
                break;
            default:
                return null;
        }

        /*
        switch (uriMatcher.match(uri)) {
            case STUDENTS:
                qb.setProjectionMap(STUDENTS_PROJECTION_MAP);
                break;

            case STUDENT_ID:
                qb.appendWhere( _ID + "=" + uri.getPathSegments().get(1));
                break;

            default:
        }

        if (sortOrder == null || sortOrder == ""){
            sortOrder = NAME;
        }
        */

        Cursor c = qb.query(db,	projection,	selection,
                selectionArgs,null, null, sortOrder);
        /**
         * register to watch a content URI for changes
         */
        c.setNotificationUri(getContext().getContentResolver(), uri);
        return c;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        int count = 0;
        /*
        switch (uriMatcher.match(uri)){
            case ACCOUNT:
                count = db.delete(ACCOUNT_TABLE_NAME, selection, selectionArgs);
                break;

            case ACCOUNT_ID:
                String id = uri.getPathSegments().get(1);
                count = db.delete( ACCOUNT_TABLE_NAME, _ID +  " = " + id +
                                (!TextUtils.isEmpty(selection) ? " AND (" + selection + ')' : ""), selectionArgs);
                break;
            default:
                throw new IllegalArgumentException("Unknown URI " + uri);
        }
        */
        int UriTableType = uriMatcher.match(uri);
        switch (UriTableType) {
            case ACCOUNT:
                count = db.delete(Tags.ACCOUNT_TABLE_NAME, selection, selectionArgs);
                break;
            case FRIEND:
                count = db.delete(Tags.FRIENDS_KEYS_TABLE_NAME, selection, selectionArgs);
                break;
            case GROUPS:
                count = db.delete(Tags.GROUPS_KEYS_TABLE_NAME, selection, selectionArgs);
                break;
            default:
                return 0;
        }

        getContext().getContentResolver().notifyChange(uri, null);
        return count;
    }

    @Override
    public int update(Uri uri, ContentValues values,
                      String selection, String[] selectionArgs) {
        int count = 0;
        /*
        switch (uriMatcher.match(uri)) {
            case ACCOUNT:
                count = db.update(ACCOUNT_TABLE_NAME, values, selection, selectionArgs);
                break;

            case ACCOUNT_ID:
                count = db.update(ACCOUNT_TABLE_NAME, values,
                        _ID + " = " + uri.getPathSegments().get(1) +
                                (!TextUtils.isEmpty(selection) ? " AND (" +selection + ')' : ""), selectionArgs);
                break;
            default:
                throw new IllegalArgumentException("Unknown URI " + uri );
        }
        */
        int UriTableType = uriMatcher.match(uri);
        switch (UriTableType) {
            case ACCOUNT:
                count = db.update(Tags.ACCOUNT_TABLE_NAME, values, selection, selectionArgs);
                break;
            case FRIEND:
                count = db.update(Tags.FRIENDS_KEYS_TABLE_NAME, values, selection, selectionArgs);
                break;
            case GROUPS:
                count = db.update(Tags.GROUPS_KEYS_TABLE_NAME, values, selection, selectionArgs);
                break;
            default:
                return 0;
        }

        getContext().getContentResolver().notifyChange(uri, null);
        return count;
    }

    @Override
    public String getType(Uri uri) {
        switch (uriMatcher.match(uri)){
            case ACCOUNT:
                return "vnd.android.cursor.dir/vnd.example.account";
            case FRIEND:
                return "vnd.android.cursor.dir/vnd.example.friend";
            case GROUPS:
                return "vnd.android.cursor.dir/vnd.example.groups";
            default:
                throw new IllegalArgumentException("Unsupported URI: " + uri);
        }
    }}
