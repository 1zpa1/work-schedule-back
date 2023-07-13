package su.serviceit.work_schedule.service;

import org.springframework.stereotype.Service;
import su.serviceit.work_schedule.model.ApplicationVersion;

import java.io.FileInputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Properties;

@Service
public class ApplicationVersionService {
    public ApplicationVersion getVersion() throws IOException {
        Properties properties = new Properties();
        FileInputStream fis = new FileInputStream("version.properties");
        properties.load(fis);
        String lastModifiedTime = properties.getProperty("LAST_MODIFIED_TIME");

        SimpleDateFormat inputDateFormat = new SimpleDateFormat("yyMMddHHmm");
        Date date = null;
        try {
            date = inputDateFormat.parse(lastModifiedTime);
        } catch (Exception e) {
            // Handle exception
        }

        SimpleDateFormat outputDateFormat = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.ENGLISH);
        String formattedDate = outputDateFormat.format(date);

        return new ApplicationVersion(formattedDate);
    }
}
