# Minimize Images

Compress the image size with JPEG format limit to the maxSize(kb), and convert to byte[] return. - Android Graphics

http://www.java2s.com/example/android/graphics/compress-the-image-size-with-jpeg-format-limit-to-the-maxsizekb-and.html

```plaintext
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class Main {
    /**//from   ww  w.ja va2 s.  c  o m
     * Compress the image size with JPEG format limit to the maxSize(kb), and convert to byte[] return.
     * @param image
     * @param maxSize
     * @return
     */
    public static byte[] compressImageToBytes(Bitmap image, int maxSize) {
        return compressImage(image, Bitmap.CompressFormat.JPEG, maxSize);
    }

    /**
     * Compress the image size with JPEG format limit to the maxSize(kb).
     * @param image
     * @param maxSize
     * @return
     */
    public static Bitmap compressImage(Bitmap image, int maxSize) {
        byte[] bytes = compressImage(image, Bitmap.CompressFormat.JPEG,
                maxSize);
        ByteArrayInputStream isBm = new ByteArrayInputStream(bytes);
        Bitmap bitmap = BitmapFactory.decodeStream(isBm, null, null);
        return bitmap;
    }

    /**
     * Compress the image size limit to the maxSize(kb).
     * @param image
     * @param compressFormat
     * @param maxSize
     * @return
     */
    public static byte[] compressImage(Bitmap image,
            Bitmap.CompressFormat compressFormat, int maxSize) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        image.compress(compressFormat, 100, baos);
        int options = 100;
        while (baos.toByteArray().length / 1024 > maxSize) {
            baos.reset();
            image.compress(compressFormat, options, baos);
            if (options <= 10) {
                options -= 2;
            } else {
                options -= 10;
            }
        }
        return baos.toByteArray();
    }
}
```

https://medium.com/@adigunhammedolalekan/how-to-resize-images-for-better-upload-download-performance-android-development-fb7297f9ec24

https://github.com/adigunhammedolalekan/easyphotoupload/blob/master/app/src/main/java/com/beem24/projects/easyphotoupload/util/Util.java


https://cloudinary.com/guides/bulk-image-resize/3-ways-to-resize-images-in-java#:~:text=You%20can%20resize%20an%20image,in%20the%20Java%20Image%20class.


https://stackoverflow.com/questions/18545246/how-to-compress-image-size


Reduce Image Size for Upload | Android Tutorial
```plaintext
https://www.youtube.com/watch?v=5WXbgXd8A9Q
https://github.com/Vysh01/AndroidImageResizer/blob/master/ImageResizer.java
import android.graphics.Bitmap;
import android.util.Log;

public class ImageResizer {

	//For Image Size 640*480, use MAX_SIZE =  307200 as 640*480 307200
    //private static long MAX_SIZE = 360000;
    //private static long THUMB_SIZE = 6553;

    public static Bitmap reduceBitmapSize(Bitmap bitmap,int MAX_SIZE) {
        double ratioSquare;
        int bitmapHeight, bitmapWidth;
        bitmapHeight = bitmap.getHeight();
        bitmapWidth = bitmap.getWidth();
        ratioSquare = (bitmapHeight * bitmapWidth) / MAX_SIZE;
        if (ratioSquare <= 1)
            return bitmap;
        double ratio = Math.sqrt(ratioSquare);
        Log.d("mylog", "Ratio: " + ratio);
        int requiredHeight = (int) Math.round(bitmapHeight / ratio);
        int requiredWidth = (int) Math.round(bitmapWidth / ratio);
        return Bitmap.createScaledBitmap(bitmap, requiredWidth, requiredHeight, true);
    }

    public static Bitmap generateThumb(Bitmap bitmap, int THUMB_SIZE) {
        double ratioSquare;
        int bitmapHeight, bitmapWidth;
        bitmapHeight = bitmap.getHeight();
        bitmapWidth = bitmap.getWidth();
        ratioSquare = (bitmapHeight * bitmapWidth) / THUMB_SIZE;
        if (ratioSquare <= 1)
            return bitmap;
        double ratio = Math.sqrt(ratioSquare);
        Log.d("mylog", "Ratio: " + ratio);
        int requiredHeight = (int) Math.round(bitmapHeight / ratio);
        int requiredWidth = (int) Math.round(bitmapWidth / ratio);
        return Bitmap.createScaledBitmap(bitmap, requiredWidth, requiredHeight, true);
    }
}
```

How to compress and reduce size(resolution) of image file from your Android App? - Android 13 API 33
```plaintext
https://www.youtube.com/watch?v=O189-gHZVAY
https://programmerworld.co/android/how-to-compress-and-reduce-the-size-of-image-file-from-your-android-app-android-13-api-33/
How to compress and reduce the size (resolution) of image file from your Android App? – Android 13 API 33
package com.programmerworld.compressmyimage;

MainActivity.java
import static android.Manifest.permission.READ_MEDIA_IMAGES;
import static android.Manifest.permission.WRITE_EXTERNAL_STORAGE;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.view.View;
import android.widget.ImageView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class MainActivity extends AppCompatActivity {
    private ImageView imageView, imageView2;
    private StorageVolume storageVolume;
    private Bitmap bitmapImage;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ActivityCompat.requestPermissions(this,
                new String[]{READ_MEDIA_IMAGES, WRITE_EXTERNAL_STORAGE},
                PackageManager.PERMISSION_GRANTED);

        imageView = findViewById(R.id.imageView);
        imageView2 = findViewById(R.id.imageView2);

        StorageManager storageManager = (StorageManager) getSystemService(STORAGE_SERVICE);
        storageVolume = storageManager.getStorageVolumes().get(0); // internal storage
        File fileInput = new File(storageVolume.getDirectory().getPath() + "/Download/images.jpeg");


        bitmapImage = BitmapFactory.decodeFile(fileInput.getPath());

        imageView.setImageBitmap(bitmapImage);
    }

    public void buttonCompressImage(View view) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        bitmapImage.compress(Bitmap.CompressFormat.JPEG, 0, byteArrayOutputStream);


        byte[] bytesArray = byteArrayOutputStream.toByteArray();
        Bitmap bitmapCompressedImage = BitmapFactory.decodeByteArray(bytesArray, 0, bytesArray.length);
        imageView2.setImageBitmap(bitmapCompressedImage);

        File fileOutput = new File(storageVolume.getDirectory().getPath() + "/Download/output1.jpeg");
        FileOutputStream fileOutputStream = new FileOutputStream(fileOutput);
        fileOutputStream.write(bytesArray);
        fileOutputStream.close();
    }
}

Manifest:
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>

    <application
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:supportsRtl="true"
        android:theme="@style/Theme.CompressMyImage"
        tools:targetApi="31">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>

Layout:
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".MainActivity">

    <Button
        android:id="@+id/button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginStart="114dp"
        android:layout_marginTop="47dp"
        android:onClick="buttonCompressImage"
        android:text="Compress Image"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent" />

    <ImageView
        android:id="@+id/imageView"
        android:layout_width="180dp"
        android:layout_height="165dp"
        android:layout_marginStart="112dp"
        android:layout_marginTop="68dp"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@+id/button"
        app:srcCompat="@drawable/ic_launcher_background" />

    <ImageView
        android:id="@+id/imageView2"
        android:layout_width="180dp"
        android:layout_height="165dp"
        android:layout_marginStart="96dp"
        android:layout_marginTop="88dp"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@+id/imageView"
        app:srcCompat="@drawable/ic_launcher_background" />
        
</androidx.constraintlayout.widget.ConstraintLayout>


```