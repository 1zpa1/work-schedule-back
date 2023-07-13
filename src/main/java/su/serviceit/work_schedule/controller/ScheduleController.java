package su.serviceit.work_schedule.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import su.serviceit.work_schedule.entity.Schedule;
import su.serviceit.work_schedule.service.ScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/schedules")
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ScheduleController {
    @Autowired
    private ScheduleService scheduleService;

    @GetMapping("admin/all")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Schedule> allSchedules() {
        return scheduleService.getAllSchedule();
    }


    @GetMapping("/{id}")
    public Schedule getScheduleById(@PathVariable Long id) {
        return scheduleService.getScheduleById(id);
    }

    @PostMapping()
    public void addSchedule(Schedule schedule) {
        scheduleService.save(schedule);
    }

    @DeleteMapping("/{id}")
    public Long deleteSchedule(@PathVariable Long id) {
        scheduleService.delete(id);
        return id;
    }
}
