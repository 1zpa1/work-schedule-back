package su.serviceit.work_schedule.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import su.serviceit.work_schedule.entity.TimeRange;
import su.serviceit.work_schedule.service.TimeRangeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/timerange/")
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class TimeRangeController {
    private TimeRangeService timeRangeService;

    @Autowired
    public TimeRangeController(TimeRangeService timeRangeService) {
        this.timeRangeService = timeRangeService;
    }

    @GetMapping("admin/all")
    @PreAuthorize("hasRole('ADMIN')")
    public List<TimeRange> getAllTimeRange() {
        return timeRangeService.getAllTimeRanges();
    }

    @PostMapping
    public void addTimeRange(@RequestBody TimeRange timeRange) {
        timeRangeService.save(timeRange);
    }

}
