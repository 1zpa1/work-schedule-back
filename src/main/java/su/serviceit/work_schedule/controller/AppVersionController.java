package su.serviceit.work_schedule.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import su.serviceit.work_schedule.model.ApplicationVersion;
import su.serviceit.work_schedule.service.ApplicationVersionService;
import java.io.IOException;

@RestController
@RequestMapping("/api")
public class AppVersionController {
    @Autowired
    private ApplicationVersionService applicationVersionService;
    @GetMapping("/version")
    public ApplicationVersion getVersion() throws IOException {
        return applicationVersionService.getVersion();
    }
}
