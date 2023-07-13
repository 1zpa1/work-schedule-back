package su.serviceit.work_schedule.dto;

import su.serviceit.work_schedule.entity.Schedule;
import su.serviceit.work_schedule.entity.TimeRange;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ScheduleDTO {
    private Long id;
    private LocalDate date;
    private List<TimeRange> timeRanges;


    // Методы преобразования

    public static ScheduleDTO toModel(Schedule schedule) {
        ScheduleDTO scheduleDTO = new ScheduleDTO();
        scheduleDTO.setId(schedule.getId());
        scheduleDTO.setDate(schedule.getDate());
        scheduleDTO.setTimeRanges(schedule.getTimeRanges());
        return scheduleDTO;
    }
}
