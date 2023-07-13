package su.serviceit.work_schedule.service;

import su.serviceit.work_schedule.entity.TimeRange;
import su.serviceit.work_schedule.repository.TimeRangeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TimeRangeService {
    @Autowired
    private TimeRangeRepository timeRangeRepository;

    public List<TimeRange> getAllTimeRanges() {
        List<TimeRange> timeRanges = timeRangeRepository.findAll();
        return timeRanges;
    }

    public TimeRange save(TimeRange timeRange) {
        return timeRangeRepository.save(timeRange);
    }


}
